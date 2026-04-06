
from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import os
import socket
import ssl
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim

from vcenter import VCenterClient

logger = logging.getLogger("sdrs-manager.sdrs")

GB = 1024 ** 3
DEFAULT_ALLOWED_POOL_NAMES = ("Pool STA", "Pool STB", "Pool STC", "Pool STD")

_CACHE_LOCK = threading.RLock()
_INVENTORY_CACHE: dict[str, dict[str, Any]] = {}
_REFRESH_EVENTS: dict[str, threading.Event] = {}  # key → Event sinalizando conclusão do refresh

# Sessões pyVmomi persistentes (uma por host/user) para evitar SmartConnect repetido
_SI_LOCK = threading.RLock()
_SI_STORE: dict[str, Any] = {}   # key -> {"si": ..., "ts": float}
_SI_SESSION_TTL_SEC = 25 * 60    # assume sessão válida por 25 min (vCenter expira em 30)


def _si_cache_key(client: VCenterClient) -> str:
    return f"{client.host}::{client.user}"


def _invalidate_si(client: VCenterClient) -> None:
    key = _si_cache_key(client)
    with _SI_LOCK:
        entry = _SI_STORE.pop(key, None)
    if entry:
        try:
            Disconnect(entry["si"])
        except Exception:
            pass


def _get_or_create_si(client: VCenterClient) -> Any:
    key = _si_cache_key(client)
    now = time.monotonic()

    with _SI_LOCK:
        entry = _SI_STORE.get(key)

    if entry and (now - entry["ts"]) < _SI_SESSION_TTL_SEC:
        return entry["si"]

    if entry:
        logger.debug("Sessão pyVmomi expirada host=%s, reconectando...", client.host)
        with _SI_LOCK:
            _SI_STORE.pop(key, None)
        try:
            Disconnect(entry["si"])
        except Exception:
            pass

    ssl_context = ssl.create_default_context()
    if not client.verify_ssl:
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(_pyvmomi_connect_timeout_sec())
    try:
        logger.info("Abrindo nova sessão pyVmomi host=%s ...", client.host)
        si = SmartConnect(
            host=client.host,
            user=client.user,
            pwd=client.password,
            sslContext=ssl_context,
        )
        logger.info("Sessão pyVmomi estabelecida host=%s", client.host)
    finally:
        socket.setdefaulttimeout(old_timeout)

    with _SI_LOCK:
        _SI_STORE[key] = {"si": si, "ts": now}

    return si


class SDRSOperationError(Exception):
    """Erro controlado para operações manuais de storage vMotion."""


FORBIDDEN_VM_MUTATION_OPERATIONS = (
    "Destroy_Task",
    "UnregisterVM",
    "UnregisterAndDestroy_Task",
    "PowerOffVM_Task",
    "ResetVM_Task",
    "RemoveAllSnapshots_Task",
    "CreateSnapshot_Task",
    "ReconfigVM_Task",
)


def _env_float(name: str, default: float, min_value: float | None = None, max_value: float | None = None) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except Exception:
        return default
    if min_value is not None:
        value = max(min_value, value)
    if max_value is not None:
        value = min(max_value, value)
    return value


def _env_int(name: str, default: int, min_value: int | None = None, max_value: int | None = None) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except Exception:
        return default
    if min_value is not None:
        value = max(min_value, value)
    if max_value is not None:
        value = min(max_value, value)
    return value


def _move_policy() -> dict[str, float | int]:
    return {
        "min_free_headroom_pct": _env_float("MOVE_MIN_FREE_HEADROOM_PCT", 15.0, 2.0, 40.0),
        "min_vm_reserve_ratio": _env_float("MOVE_MIN_VM_RESERVE_RATIO", 0.10, 0.0, 1.0),
        "max_target_used_pct": _env_float("MOVE_MAX_TARGET_USED_PCT", 95.0, 70.0, 99.5),
        "max_concurrent_per_cluster": _env_int("MOVE_MAX_CONCURRENT_PER_CLUSTER", 2, 1, 20),
    }


def _cluster_cache_ttl_sec() -> int:
    return _env_int("VCENTER_CLUSTER_CACHE_TTL_SEC", 20, 1, 300)


def _vm_cache_ttl_sec() -> int:
    return _env_int("VCENTER_VM_CACHE_TTL_SEC", 20, 1, 300)


def _cache_key(client: VCenterClient) -> str:
    return f"{client.host}|{client.user}"


def _normalize_pool_name(name: str) -> str:
    return "".join(ch for ch in str(name or "").upper() if ch.isalnum())


def _allowed_pool_names() -> set[str]:
    raw = (os.getenv("ALLOWED_DATASTORE_POOLS") or "").strip()
    if raw:
        source = [item.strip() for item in raw.split(",") if item.strip()]
    else:
        source = list(DEFAULT_ALLOWED_POOL_NAMES)
    return {_normalize_pool_name(name) for name in source}


def _is_allowed_pool_name(name: str, allowed_tokens: set[str] | None = None) -> bool:
    normalized = _normalize_pool_name(name)
    allowed = allowed_tokens if allowed_tokens is not None else _allowed_pool_names()
    return any(normalized == token or normalized.startswith(token) for token in allowed)


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _to_gb(value: Any) -> float | None:
    try:
        if value is None:
            return None
        return round(float(value) / GB, 2)
    except Exception:
        return None


def _normalize_power_state(value: Any) -> str:
    state = str(value or "unknown")
    if "." in state:
        state = state.split(".")[-1]
    return state


def _safe_get(obj: Any, *attrs: str, default: Any = None) -> Any:
    if obj is None:
        return default
    for attr in attrs:
        try:
            value = getattr(obj, attr)
            if value is not None:
                return value
        except Exception:
            continue
    return default


def _extract_numeric_values(raw: Any) -> list[float]:
    if raw is None:
        return []

    if isinstance(raw, (list, tuple)):
        items = raw
    else:
        try:
            items = list(raw)
            if isinstance(raw, (str, bytes)):
                items = [raw]
        except Exception:
            items = [raw]

    numeric: list[float] = []
    for item in items:
        try:
            numeric.append(float(item))
        except Exception:
            continue
    return numeric


def _mean_or_none(raw: Any) -> float | None:
    numeric = _extract_numeric_values(raw)
    if not numeric:
        return None
    return round(sum(numeric) / len(numeric), 2)


def _pyvmomi_connect_timeout_sec() -> int:
    return _env_int("PYVMOMI_CONNECT_TIMEOUT_SEC", 45, 5, 300)


@contextmanager
def _service_instance(client: VCenterClient) -> Iterator[Any]:
    """Retorna a sessão pyVmomi persistente com timeout em todos os calls de rede."""
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(_pyvmomi_connect_timeout_sec())
    try:
        si = _get_or_create_si(client)
        yield si
    except Exception:
        _invalidate_si(client)
        raise
    finally:
        socket.setdefaulttimeout(old_timeout)


@contextmanager
def _view(content: Any, vim_types: list[Any]) -> Iterator[list[Any]]:
    view = None
    try:
        view = content.viewManager.CreateContainerView(content.rootFolder, vim_types, True)
        yield list(view.view or [])
    finally:
        if view is not None:
            try:
                view.Destroy()
            except Exception:
                logger.debug("Falha ao destruir ContainerView", exc_info=True)


def _estimate_vm_size_bytes(vm_obj: Any) -> int | None:
    summary_storage = getattr(getattr(vm_obj, "summary", None), "storage", None)
    if summary_storage is not None:
        committed = _to_int(getattr(summary_storage, "committed", None), 0)
        uncommitted = _to_int(getattr(summary_storage, "uncommitted", None), 0)
        if committed > 0:
            return committed
        if committed > 0 or uncommitted > 0:
            return max(committed + uncommitted, 0)

    usage = list(getattr(getattr(vm_obj, "storage", None), "perDatastoreUsage", []) or [])
    if usage:
        committed_sum = sum(_to_int(getattr(item, "committed", None), 0) for item in usage)
        if committed_sum > 0:
            return committed_sum

    devices = list(getattr(getattr(getattr(vm_obj, "config", None), "hardware", None), "device", []) or [])
    capacity = 0
    for dev in devices:
        if isinstance(dev, vim.vm.device.VirtualDisk):
            capacity += _to_int(getattr(dev, "capacityInBytes", None), 0)
    return capacity if capacity > 0 else None


def _primary_vm_datastore(vm_obj: Any) -> Any | None:
    usage = list(getattr(getattr(vm_obj, "storage", None), "perDatastoreUsage", []) or [])
    if usage:
        return getattr(usage[0], "datastore", None)
    datastores = list(getattr(vm_obj, "datastore", []) or [])
    return datastores[0] if datastores else None


def _serialize_datastore(ds_obj: Any) -> dict[str, Any]:
    summary = getattr(ds_obj, "summary", None)
    capacity = _to_float(getattr(summary, "capacity", None), 0.0)
    free = _to_float(getattr(summary, "freeSpace", None), 0.0)
    uncommitted = _to_float(getattr(summary, "uncommitted", None), 0.0)
    provisioned = max(0.0, (capacity - free) + max(uncommitted, 0.0))
    used_pct = round(((capacity - free) / capacity) * 100.0, 2) if capacity > 0 else 0.0

    return {
        "id": getattr(ds_obj, "_moId", None),
        "name": str(getattr(ds_obj, "name", "")),
        "moref_id": getattr(ds_obj, "_moId", None),
        "capacity_gb": _to_gb(capacity),
        "provisioned_gb": _to_gb(provisioned),
        "free_gb": _to_gb(free),
        "used_pct": used_pct,
        "latency_ms": None,
        "accessible": bool(getattr(summary, "accessible", True)),
        "_capacity_bytes": capacity,
        "_free_bytes": free,
        "_obj": ds_obj,
    }


def _serialize_vm(vm_obj: Any) -> dict[str, Any]:
    ds = _primary_vm_datastore(vm_obj)
    size_bytes = _estimate_vm_size_bytes(vm_obj)
    return {
        "vm_id": getattr(vm_obj, "_moId", None),
        "vm_name": str(getattr(vm_obj, "name", "")),
        "size_gb": _to_gb(size_bytes),
        "power_state": _normalize_power_state(getattr(getattr(vm_obj, "runtime", None), "powerState", None)),
        "home_datastore": getattr(ds, "name", None),
        "home_datastore_id": getattr(ds, "_moId", None),
        "_obj": vm_obj,
    }


def _pod_sdrs_enabled(pod_obj: Any) -> bool:
    try:
        entry = getattr(pod_obj, "podStorageDrsEntry", None)
        cfg = getattr(entry, "storageDrsConfig", None)
        pod_cfg = getattr(cfg, "podConfig", None)
        enabled = getattr(pod_cfg, "enabled", None)
        return bool(enabled) if enabled is not None else False
    except Exception:
        return False


def _serialize_cluster_from_pod(pod_obj: Any) -> dict[str, Any]:
    datastores: list[dict[str, Any]] = []
    for child in list(getattr(pod_obj, "childEntity", []) or []):
        if isinstance(child, vim.Datastore):
            datastores.append(_serialize_datastore(child))
    datastores.sort(key=lambda x: str(x.get("name") or "").lower())
    return {
        "id": getattr(pod_obj, "_moId", None),
        "name": str(getattr(pod_obj, "name", "")),
        "sdrs_enabled": _pod_sdrs_enabled(pod_obj),
        "datastores": datastores,
    }


def _latency_from_srm_summary_item(summary: Any) -> float | None:
    vm_latency = _mean_or_none(_safe_get(summary, "datastoreVmLatency", "vmLatency", "overallLatency"))
    read_latency = _mean_or_none(_safe_get(summary, "datastoreReadLatency", "readLatency"))
    write_latency = _mean_or_none(_safe_get(summary, "datastoreWriteLatency", "writeLatency"))

    if vm_latency is not None:
        return vm_latency

    dual = [value for value in (read_latency, write_latency) if value is not None]
    if dual:
        return round(sum(dual) / len(dual), 2)

    return None


def _collect_datastore_latency_via_srm(content: Any, datastores: list[dict[str, Any]]) -> dict[str, float | None]:
    srm = getattr(content, "storageResourceManager", None)
    if srm is None or not hasattr(srm, "QueryDatastorePerformanceSummary"):
        return {}

    ds_objs: list[Any] = []
    ds_ids: list[str] = []
    for ds in datastores:
        ds_obj = ds.get("_obj")
        ds_id = str(ds.get("id") or "")
        if ds_obj is None or not ds_id:
            continue
        ds_objs.append(ds_obj)
        ds_ids.append(ds_id)

    if not ds_objs:
        return {}

    try:
        try:
            raw = srm.QueryDatastorePerformanceSummary(datastore=ds_objs)
        except TypeError:
            # Ambientes legados podem exigir datastore por chamada.
            raw_items: list[Any] = []
            for ds_obj in ds_objs:
                one = srm.QueryDatastorePerformanceSummary(datastore=[ds_obj])
                if isinstance(one, list):
                    raw_items.extend(one)
                elif one is not None:
                    raw_items.append(one)
            raw = raw_items
    except Exception:
        logger.debug("QueryDatastorePerformanceSummary indisponível/falhou", exc_info=True)
        return {}

    items = raw if isinstance(raw, list) else [raw]
    if not items:
        return {}

    latency_by_ds: dict[str, float | None] = {}
    indexed = False
    for item in items:
        entity = _safe_get(item, "datastore", "entity")
        ds_id = str(getattr(entity, "_moId", "") or _safe_get(item, "datastoreId", "id", default="") or "")
        if not ds_id:
            continue
        latency = _latency_from_srm_summary_item(item)
        if latency is not None:
            latency_by_ds[ds_id] = latency
            indexed = True

    # Fallback por ordem de retorno quando id não vier no summary.
    if not indexed and len(items) == len(ds_ids):
        for idx, item in enumerate(items):
            latency = _latency_from_srm_summary_item(item)
            if latency is not None:
                latency_by_ds[ds_ids[idx]] = latency

    return latency_by_ds


def _resolve_datastore_latency_counter_ids(content: Any) -> tuple[list[int], list[int], dict[int, str]]:
    perf_manager = getattr(content, "perfManager", None)
    if perf_manager is None:
        return [], [], {}

    read_counter_ids: list[int] = []
    write_counter_ids: list[int] = []
    counter_name_by_id: dict[int, str] = {}

    try:
        for counter in list(getattr(perf_manager, "perfCounter", []) or []):
            group_info = getattr(counter, "groupInfo", None)
            name_info = getattr(counter, "nameInfo", None)

            group = str(getattr(group_info, "key", "") or "").lower()
            name = str(getattr(name_info, "key", "") or "").lower()

            if group != "datastore" or "latency" not in name:
                continue

            cid = int(getattr(counter, "key", 0) or 0)
            if cid <= 0:
                continue

            counter_name_by_id[cid] = name
            if "read" in name:
                read_counter_ids.append(cid)
            if "write" in name:
                write_counter_ids.append(cid)
    except Exception:
        logger.debug("Falha ao resolver counters de latência de datastore", exc_info=True)

    def _dedupe_sorted(ids: list[int]) -> list[int]:
        unique = sorted(set(ids), key=lambda cid: counter_name_by_id.get(cid, ""))
        return sorted(
            unique,
            key=lambda cid: (
                0 if counter_name_by_id.get(cid, "").startswith("total") else 1,
                counter_name_by_id.get(cid, ""),
            ),
        )

    return _dedupe_sorted(read_counter_ids), _dedupe_sorted(write_counter_ids), counter_name_by_id


def _build_metric_ids(counter_ids: list[int]) -> list[Any]:
    metric_ids: list[Any] = []
    seen: set[tuple[int, str]] = set()
    for counter_id in counter_ids:
        for instance in ("", "*"):
            key = (int(counter_id), instance)
            if key in seen:
                continue
            seen.add(key)
            metric_ids.append(vim.PerformanceManager.MetricId(counterId=int(counter_id), instance=instance))
    return metric_ids


def _build_query_spec(
    entity: Any,
    metric_ids: list[Any],
    interval_id: int | None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> Any:
    kwargs: dict[str, Any] = {
        "entity": entity,
        "metricId": metric_ids,
        "maxSample": 1,
    }
    if interval_id is not None and interval_id > 0:
        kwargs["intervalId"] = int(interval_id)
    if start_time is not None:
        kwargs["startTime"] = start_time
    if end_time is not None:
        kwargs["endTime"] = end_time
    return vim.PerformanceManager.QuerySpec(**kwargs)


def _resolve_interval_id(perf_manager: Any, ds_obj: Any) -> int | None:
    try:
        summary = perf_manager.QueryPerfProviderSummary(entity=ds_obj)
        refresh_rate = int(getattr(summary, "refreshRate", -1) or -1)
        if refresh_rate > 0:
            return refresh_rate
    except Exception:
        logger.debug("Não foi possível resolver refreshRate de PerformanceManager", exc_info=True)
    return None


def _historical_interval_ids(perf_manager: Any) -> list[int]:
    ids: list[int] = []
    try:
        intervals = list(getattr(perf_manager, "historicalInterval", []) or [])
        for item in intervals:
            sampling = int(getattr(item, "samplingPeriod", 0) or 0)
            if sampling > 0 and sampling not in ids:
                ids.append(sampling)
    except Exception:
        logger.debug("Falha ao ler historicalInterval do PerformanceManager", exc_info=True)
    return sorted(ids)


def _extract_latency_values_by_ds(
    results: list[Any],
    read_counter_ids: set[int],
    write_counter_ids: set[int],
) -> dict[str, list[float]]:
    values_by_ds: dict[str, list[float]] = {}
    for entity_metric in list(results or []):
        entity = getattr(entity_metric, "entity", None)
        ds_id = str(getattr(entity, "_moId", "") or "")
        if not ds_id:
            continue

        read_values: list[float] = []
        write_values: list[float] = []
        other_values: list[float] = []
        for series in list(getattr(entity_metric, "value", []) or []):
            samples = list(getattr(series, "value", []) or [])
            if not samples:
                continue
            sample = samples[-1]
            try:
                sample_value = float(sample)
            except Exception:
                continue
            if sample_value < 0:
                continue

            metric_id = getattr(series, "id", None)
            counter_id = int(getattr(metric_id, "counterId", 0) or 0)
            if counter_id in read_counter_ids:
                read_values.append(sample_value)
            elif counter_id in write_counter_ids:
                write_values.append(sample_value)
            else:
                other_values.append(sample_value)

        merged = read_values + write_values
        values_by_ds[ds_id] = merged if merged else other_values
    return values_by_ds


def _collect_datastore_latency_ms(content: Any, datastores: list[dict[str, Any]]) -> dict[str, float | None]:
    if not datastores:
        return {}

    latency_by_ds = _collect_datastore_latency_via_srm(content, datastores)
    unresolved_ids = {
        str(ds.get("id") or "")
        for ds in datastores
        if ds.get("id") is not None and str(ds.get("id") or "") not in latency_by_ds
    }
    if not unresolved_ids:
        return latency_by_ds

    perf_manager = getattr(content, "perfManager", None)
    if perf_manager is None:
        return latency_by_ds

    read_counter_ids, write_counter_ids, name_by_id = _resolve_datastore_latency_counter_ids(content)
    target_counter_ids = list(read_counter_ids) + list(write_counter_ids)
    if not target_counter_ids:
        target_counter_ids = sorted(name_by_id.keys())
    metric_ids = _build_metric_ids(target_counter_ids)
    if not metric_ids:
        return latency_by_ds

    datastore_objs: dict[str, Any] = {}
    sample_ds_obj: Any | None = None
    for ds in datastores:
        ds_obj = ds.get("_obj")
        ds_id = str(ds.get("id") or "")
        if ds_obj is None or not ds_id or ds_id not in unresolved_ids:
            continue
        if sample_ds_obj is None:
            sample_ds_obj = ds_obj
        datastore_objs[ds_id] = ds_obj

    if not datastore_objs:
        return latency_by_ds

    realtime_interval = _resolve_interval_id(perf_manager, sample_ds_obj) if sample_ds_obj is not None else None
    historical_ids = _historical_interval_ids(perf_manager)
    now = datetime.now(timezone.utc)
    query_strategies: list[tuple[int | None, datetime | None, datetime | None]] = []

    if realtime_interval is not None and realtime_interval > 0:
        query_strategies.append((realtime_interval, None, None))
    query_strategies.append((None, None, None))
    for interval_id in historical_ids:
        lookback_sec = max(1800, int(interval_id) * 8)
        start_time = now - timedelta(seconds=lookback_sec)
        query_strategies.append((interval_id, start_time, now))

    read_id_set = set(read_counter_ids)
    write_id_set = set(write_counter_ids)
    values_by_ds: dict[str, list[float]] = {}
    for interval_id, start_time, end_time in query_strategies:
        specs: list[Any] = []
        for ds_obj in datastore_objs.values():
            specs.append(
                _build_query_spec(
                    ds_obj,
                    metric_ids,
                    interval_id=interval_id,
                    start_time=start_time,
                    end_time=end_time,
                )
            )
        if not specs:
            continue
        try:
            results = perf_manager.QueryPerf(querySpec=specs) or []
            values_by_ds = _extract_latency_values_by_ds(results, read_id_set, write_id_set)
            if values_by_ds:
                break
        except Exception:
            logger.debug(
                "QueryPerf em lote falhou (interval=%s)",
                interval_id,
                exc_info=True,
            )

    if not values_by_ds:
        for ds_id, ds_obj in datastore_objs.items():
            try:
                for interval_id, start_time, end_time in query_strategies:
                    available_kwargs: dict[str, Any] = {"entity": ds_obj}
                    if interval_id is not None and interval_id > 0:
                        available_kwargs["intervalId"] = int(interval_id)
                    available_metrics = perf_manager.QueryAvailablePerfMetric(**available_kwargs) or []
                    available_counter_ids = {int(getattr(item, "counterId", 0) or 0) for item in available_metrics}
                    allowed_ids = [cid for cid in target_counter_ids if cid in available_counter_ids]
                    if not allowed_ids:
                        continue
                    query_spec = _build_query_spec(
                        ds_obj,
                        _build_metric_ids(allowed_ids),
                        interval_id=interval_id,
                        start_time=start_time,
                        end_time=end_time,
                    )
                    partial_results = perf_manager.QueryPerf(querySpec=[query_spec]) or []
                    partial_values = _extract_latency_values_by_ds(partial_results, read_id_set, write_id_set)
                    if ds_id in partial_values and partial_values[ds_id]:
                        values_by_ds[ds_id] = partial_values[ds_id]
                        break
            except Exception:
                logger.debug("Fallback de latência falhou para datastore %s", ds_id, exc_info=True)

    for ds_id, values in values_by_ds.items():
        if not values:
            continue
        latency_by_ds[ds_id] = round(sum(values) / len(values), 2)

    return latency_by_ds


def _fetch_clusters_from_content(content: Any) -> dict[str, dict[str, Any]]:
    clusters: dict[str, dict[str, Any]] = {}
    allowed_tokens = _allowed_pool_names()
    with _view(content, [vim.StoragePod]) as pod_view:
        for pod_obj in pod_view:
            pod_name = str(getattr(pod_obj, "name", "") or "")
            if not _is_allowed_pool_name(pod_name, allowed_tokens=allowed_tokens):
                continue
            cluster = _serialize_cluster_from_pod(pod_obj)
            cluster_id = str(cluster.get("id") or "")
            if cluster_id:
                clusters[cluster_id] = cluster

    all_datastores: list[dict[str, Any]] = []
    for cluster in clusters.values():
        all_datastores.extend(list(cluster.get("datastores", []) or []))

    latency_timeout = _env_int("LATENCY_COLLECT_TIMEOUT_SEC", 20, 5, 120)
    latency_by_ds: dict[str, float | None] = {}
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    try:
        future = ex.submit(_collect_datastore_latency_ms, content, all_datastores)
        latency_by_ds = future.result(timeout=latency_timeout)
    except concurrent.futures.TimeoutError:
        logger.warning(
            "Coleta de latência ultrapassou %ss — retornando clusters sem latência neste ciclo.",
            latency_timeout,
        )
    except Exception as exc:
        logger.debug("Coleta de latência falhou: %s", exc)
    finally:
        # Não bloquear o fluxo principal aguardando worker de latência.
        ex.shutdown(wait=False, cancel_futures=True)

    if latency_by_ds:
        for cluster in clusters.values():
            for ds in list(cluster.get("datastores", []) or []):
                ds_id = str(ds.get("id") or "")
                if ds_id and ds_id in latency_by_ds:
                    ds["latency_ms"] = latency_by_ds.get(ds_id)

    return dict(sorted(clusters.items(), key=lambda item: str(item[1].get("name") or "").lower()))


def _fetch_vms_from_content(content: Any) -> list[dict[str, Any]]:
    with _view(content, [vim.VirtualMachine]) as vm_view:
        vms = [_serialize_vm(vm_obj) for vm_obj in vm_view]
    vms.sort(key=lambda x: str(x.get("vm_name") or "").lower())
    return vms


def _fetch_clusters_sync(client: VCenterClient) -> dict[str, dict[str, Any]]:
    with _service_instance(client) as si:
        content = si.RetrieveContent()
        return _fetch_clusters_from_content(content)


def _fetch_vms_sync(client: VCenterClient) -> list[dict[str, Any]]:
    with _service_instance(client) as si:
        content = si.RetrieveContent()
        return _fetch_vms_from_content(content)


def _fetch_inventory_sync(client: VCenterClient) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    with _service_instance(client) as si:
        content = si.RetrieveContent()
        clusters = _fetch_clusters_from_content(content)
        vms = _fetch_vms_from_content(content)
    return clusters, vms


def _update_cache(key: str, clusters: dict | None, vms: list | None, now: float) -> None:
    with _CACHE_LOCK:
        entry = _INVENTORY_CACHE.get(key, {})
        if clusters is not None:
            entry["clusters"] = clusters
            entry["cluster_ts"] = now
        if vms is not None:
            entry["vms"] = vms
            entry["vm_ts"] = now
        _INVENTORY_CACHE[key] = entry


def _get_or_create_refresh_event(key: str) -> tuple[threading.Event, bool]:
    """Retorna (event, created). created=True se este thread deve executar o refresh."""
    with _CACHE_LOCK:
        if key in _REFRESH_EVENTS:
            return _REFRESH_EVENTS[key], False
        event = threading.Event()
        _REFRESH_EVENTS[key] = event
        return event, True


def _background_refresh(client: VCenterClient, do_clusters: bool, do_vms: bool) -> threading.Event | None:
    key = _cache_key(client)
    event, is_owner = _get_or_create_refresh_event(key)
    if not is_owner:
        return event  # já há um refresh em andamento — retorna o event existente

    def _run() -> None:
        try:
            now = time.monotonic()
            clusters: dict | None = None
            vms: list | None = None
            if do_clusters and do_vms:
                clusters, vms = _fetch_inventory_sync(client)
            elif do_clusters:
                clusters = _fetch_clusters_sync(client)
            elif do_vms:
                vms = _fetch_vms_sync(client)
            _update_cache(key, clusters, vms, now)
            logger.info("Cache atualizado em background host=%s", client.host)
        except Exception as exc:
            logger.warning("Falha no refresh em background host=%s: %s", client.host, exc)
        finally:
            with _CACHE_LOCK:
                _REFRESH_EVENTS.pop(key, None)
            event.set()

    threading.Thread(target=_run, daemon=True, name=f"vcenter-refresh-{client.host}").start()
    return event


def _get_cached_inventory_sync(
    client: VCenterClient,
    include_vms: bool,
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    now = time.monotonic()
    key = _cache_key(client)

    with _CACHE_LOCK:
        entry = _INVENTORY_CACHE.get(key, {})
        has_clusters = "clusters" in entry
        has_vms = "vms" in entry
        cluster_ts = float(entry.get("cluster_ts", 0.0))
        vm_ts = float(entry.get("vm_ts", 0.0))

    refresh_clusters = (not has_clusters) or ((now - cluster_ts) >= _cluster_cache_ttl_sec())
    refresh_vms = include_vms and ((not has_vms) or ((now - vm_ts) >= _vm_cache_ttl_sec()))

    if refresh_clusters or refresh_vms:
        if has_clusters or (not refresh_clusters):
            # Tem dados em cache (stale) — retorna imediatamente e atualiza em background
            _background_refresh(client, refresh_clusters, refresh_vms and include_vms)
        else:
            # Sem dados — dispara background refresh e aguarda (com timeout) sua conclusão
            wait_sec = _env_int("INVENTORY_WAIT_TIMEOUT_SEC", 300, 10, 600)
            event = _background_refresh(client, refresh_clusters, refresh_vms and include_vms)
            if event is not None:
                logger.info("Aguardando carga inicial do inventário vCenter (max %ss)...", wait_sec)
                event.wait(timeout=wait_sec)
                logger.info("Carga inicial concluída ou timeout atingido.")

    with _CACHE_LOCK:
        entry = _INVENTORY_CACHE.get(key, {})
        cached_clusters = dict(entry.get("clusters", {}) or {})
        cached_vms = list(entry.get("vms", []) or [])

    if include_vms:
        return cached_clusters, cached_vms
    return cached_clusters, []


def _cluster_inventory_sync(client: VCenterClient) -> dict[str, dict[str, Any]]:
    clusters, _ = _get_cached_inventory_sync(client, include_vms=False)
    return clusters


def _inventory_sync(client: VCenterClient) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    return _get_cached_inventory_sync(client, include_vms=True)


def _invalidate_inventory_cache(client: VCenterClient) -> None:
    with _CACHE_LOCK:
        _INVENTORY_CACHE.pop(_cache_key(client), None)


def _cluster_summary(cluster: dict[str, Any]) -> dict[str, Any]:
    datastores = list(cluster.get("datastores", []) or [])
    total_free = round(sum(_to_float(ds.get("free_gb"), 0.0) for ds in datastores), 2)
    total_capacity = round(sum(_to_float(ds.get("capacity_gb"), 0.0) for ds in datastores), 2)
    sdrs_enabled = bool(cluster.get("sdrs_enabled", False))
    return {
        "id": cluster.get("id"),
        "name": cluster.get("name"),
        "sdrs_enabled": sdrs_enabled,
        "sdrs_automation_level": "Manual",
        "free_space_threshold": None,
        "io_latency_threshold": None,
        "datastore_count": len(datastores),
        "total_free_gb": total_free,
        "total_capacity_gb": total_capacity,
    }


def _cluster_detail(cluster: dict[str, Any]) -> dict[str, Any]:
    datastores = list(cluster.get("datastores", []) or [])
    sdrs_enabled = bool(cluster.get("sdrs_enabled", False))
    return {
        "id": cluster.get("id"),
        "name": cluster.get("name"),
        "sdrs_enabled": sdrs_enabled,
        "sdrs_automation_level": "Manual",
        "free_space_threshold": None,
        "io_latency_threshold": None,
        "datastore_count": len(datastores),
        "datastores": [
            {
                "id": ds.get("id"),
                "name": ds.get("name"),
                "capacity_gb": ds.get("capacity_gb"),
                "free_gb": ds.get("free_gb"),
                "used_pct": ds.get("used_pct"),
                "latency_ms": ds.get("latency_ms"),
            }
            for ds in datastores
        ],
    }


def _find_datastore(datastores: list[dict[str, Any]], datastore_id: str) -> dict[str, Any] | None:
    for ds in datastores:
        if ds.get("id") == datastore_id:
            return ds
    return None


def _find_vm(vms: list[dict[str, Any]], vm_id: str) -> dict[str, Any] | None:
    for vm in vms:
        if vm.get("vm_id") == vm_id:
            return vm
    return None


def _calc_used_pct(capacity_bytes: float, free_bytes: float) -> float | None:
    if capacity_bytes <= 0:
        return None
    return round(((capacity_bytes - free_bytes) / capacity_bytes) * 100.0, 2)


def _calc_free_pct(capacity_bytes: float, free_bytes: float) -> float | None:
    if capacity_bytes <= 0:
        return None
    return round((free_bytes / capacity_bytes) * 100.0, 2)


def _compatibility(target_capacity: float, target_free: float, vm_size: float, policy: dict[str, float | int]) -> tuple[bool, list[str], float, float | None, float | None]:
    reasons: list[str] = []
    reserve_ratio = _to_float(policy.get("min_vm_reserve_ratio"), 0.1)
    min_required = vm_size * (1.0 + reserve_ratio)

    projected_free = target_free - vm_size
    projected_used_pct = _calc_used_pct(target_capacity, projected_free)
    projected_free_pct = _calc_free_pct(target_capacity, projected_free)

    if projected_free < 0 or target_free < min_required:
        reasons.append("insufficient_free_space_with_reserve")

    max_target_used_pct = _to_float(policy.get("max_target_used_pct"), 95.0)
    if projected_used_pct is not None and projected_used_pct > max_target_used_pct:
        reasons.append("projected_usage_too_high")

    return len(reasons) == 0, reasons, projected_free, projected_free_pct, projected_used_pct


def _normalize_task_state(raw: Any) -> str:
    state = str(raw or "unknown")
    if "." in state:
        state = state.split(".")[-1]
    state = state.lower()
    return state if state in {"queued", "running", "success", "error"} else "unknown"


def _find_task(content: Any, task_id: str) -> Any | None:
    # Primeiro tenta no recentTask do TaskManager, que costuma reter
    # tarefas concluídas por mais tempo que a view genérica de vim.Task.
    task_manager = getattr(content, "taskManager", None)
    if task_manager is not None:
        try:
            for task in list(getattr(task_manager, "recentTask", []) or []):
                if getattr(task, "_moId", None) == task_id:
                    return task
        except Exception:
            logger.debug("Falha ao buscar task em taskManager.recentTask", exc_info=True)

    # Fallback para varredura de tasks visíveis no inventário.
    with _view(content, [vim.Task]) as tasks:
        for task in tasks:
            if getattr(task, "_moId", None) == task_id:
                return task
    return None


def _to_iso_or_none(value: Any) -> str | None:
    if value is None:
        return None
    try:
        return value.isoformat()
    except Exception:
        return str(value)


def _enforce_storage_relocate_only(vm_obj: Any) -> None:
    if vm_obj is None:
        raise SDRSOperationError("VM inválida para operação de migração.")
    if not hasattr(vm_obj, "RelocateVM_Task"):
        raise SDRSOperationError("VM não suporta operação de RelocateVM_Task.")


def _list_clusters_sync(client: VCenterClient) -> list[dict[str, Any]]:
    clusters = _cluster_inventory_sync(client)
    return [_cluster_summary(cluster) for cluster in clusters.values()]


def _get_cluster_detail_sync(client: VCenterClient, cluster_id: str) -> dict[str, Any]:
    clusters = _cluster_inventory_sync(client)
    cluster = clusters.get(cluster_id)
    if cluster is None:
        return {}
    return _cluster_detail(cluster)


def _get_pending_recommendations_sync(client: VCenterClient, cluster_id: str) -> list[dict[str, Any]]:
    _ = client
    _ = cluster_id
    return []


def _build_move_candidates_sync(client: VCenterClient, cluster_id: str, limit: int = 20) -> dict[str, Any]:
    clusters = _cluster_inventory_sync(client)
    cluster = clusters.get(cluster_id)
    _ = limit
    cluster_name = cluster.get("name") if cluster else None
    return {
        "cluster_id": cluster_id,
        "cluster_name": cluster_name,
        "policy": _move_policy(),
        "items": [],
        "reason": "ok" if cluster else "cluster_not_found",
    }


def _build_simulated_plan_sync(client: VCenterClient, cluster_id: str, max_moves: int = 3) -> dict[str, Any]:
    clusters = _cluster_inventory_sync(client)
    cluster = clusters.get(cluster_id)
    datastores = list(cluster.get("datastores", []) or []) if cluster else []
    used_values = [
        _to_float(ds.get("used_pct"), 0.0)
        for ds in datastores
        if ds.get("used_pct") is not None
    ]
    avg_used = round(sum(used_values) / len(used_values), 2) if used_values else 0.0
    max_used = round(max(used_values), 2) if used_values else 0.0
    min_used = round(min(used_values), 2) if used_values else 0.0
    imbalance = round(max_used - min_used, 2) if used_values else 0.0

    return {
        "cluster_id": cluster_id,
        "cluster_name": cluster.get("name") if cluster else None,
        "max_moves": max_moves,
        "policy": _move_policy(),
        "before": {"avg_used_pct": avg_used, "space_imbalance_pct": imbalance},
        "after": {"avg_used_pct": avg_used, "space_imbalance_pct": imbalance},
        "delta": {"avg_used_pct_delta": 0.0, "space_imbalance_pct_delta": 0.0},
        "source_candidates": 0,
        "items": [],
        "reason": "ok" if cluster else "cluster_not_found",
    }


def _diagnose_latency_collection_sync(client: VCenterClient, cluster_id: str | None = None, max_datastores_per_cluster: int = 3) -> dict[str, Any]:
    safe_limit = max(1, min(int(max_datastores_per_cluster), 20))

    with _service_instance(client) as si:
        content = si.RetrieveContent()
        clusters = _fetch_clusters_from_content(content)

        perf_manager = getattr(content, "perfManager", None)
        srm = getattr(content, "storageResourceManager", None)
        srm_available = bool(srm is not None and hasattr(srm, "QueryDatastorePerformanceSummary"))
        read_ids: list[int] = []
        write_ids: list[int] = []
        if perf_manager is not None:
            read_ids, write_ids, _ = _resolve_datastore_latency_counter_ids(content)

    cluster_reports: list[dict[str, Any]] = []
    total_datastores = 0
    total_with_latency = 0
    selected_ids: set[str] = {cluster_id} if cluster_id else set(clusters.keys())

    for cid, cluster in clusters.items():
        if cid not in selected_ids:
            continue
        datastores = list(cluster.get("datastores", []) or [])
        total_datastores += len(datastores)
        nonnull = sum(1 for ds in datastores if ds.get("latency_ms") is not None)
        total_with_latency += nonnull
        cluster_reports.append(
            {
                "cluster_id": cid,
                "cluster_name": cluster.get("name"),
                "datastore_count": len(datastores),
                "latency_nonnull_count": nonnull,
                "latency_null_count": max(0, len(datastores) - nonnull),
                "sample_datastores": [
                    {
                        "datastore_id": ds.get("id"),
                        "datastore_name": ds.get("name"),
                        "latency_ms": ds.get("latency_ms"),
                    }
                    for ds in datastores[:safe_limit]
                ],
            }
        )

    if total_datastores == 0:
        msg = "Nenhum datastore encontrado para os pools permitidos."
    elif total_with_latency == 0:
        msg = (
            "Nenhuma latência retornada pelo vCenter para os datastores atuais. "
            "Verifique permissões/performance level do usuário de serviço."
        )
    else:
        msg = "Latência coletada com sucesso para parte dos datastores."

    return {
        "host": client.host,
        "cluster_filter": cluster_id,
        "message": msg,
        "perf_manager_available": perf_manager is not None,
        "srm_available": srm_available,
        "latency_counter_ids": {
            "read": read_ids,
            "write": write_ids,
        },
        "clusters": cluster_reports,
    }

def _list_datastore_vms_sync(client: VCenterClient, cluster_id: str, datastore_id: str) -> dict[str, Any]:
    clusters, vms = _inventory_sync(client)
    cluster = clusters.get(cluster_id)

    if cluster is None:
        return {
            "cluster_id": cluster_id,
            "cluster_name": None,
            "datastore_id": datastore_id,
            "datastore_name": None,
            "items": [],
            "reason": "cluster_not_found",
        }

    datastores = list(cluster.get("datastores", []) or [])
    ds = _find_datastore(datastores, datastore_id)
    if ds is None:
        return {
            "cluster_id": cluster_id,
            "cluster_name": cluster.get("name"),
            "datastore_id": datastore_id,
            "datastore_name": None,
            "items": [],
            "reason": "datastore_not_found",
        }

    items = [
        {
            "vm_id": vm.get("vm_id"),
            "vm_name": vm.get("vm_name"),
            "size_gb": vm.get("size_gb"),
            "power_state": vm.get("power_state"),
            "home_datastore": vm.get("home_datastore"),
        }
        for vm in vms
        if vm.get("home_datastore_id") == datastore_id
    ]

    return {
        "cluster_id": cluster_id,
        "cluster_name": cluster.get("name"),
        "datastore_id": datastore_id,
        "datastore_name": ds.get("name"),
        "items": items,
        "reason": "ok",
    }


def _move_options_for_vm_sync(client: VCenterClient, cluster_id: str, vm_id: str, source_datastore_id: str | None = None) -> dict[str, Any]:
    clusters, vms = _inventory_sync(client)
    policy = _move_policy()
    cluster = clusters.get(cluster_id)

    if cluster is None:
        return {
            "cluster_id": cluster_id,
            "cluster_name": None,
            "vm_id": vm_id,
            "vm_name": None,
            "source_datastore_id": source_datastore_id,
            "source_datastore_name": None,
            "vm_size_gb": None,
            "policy": policy,
            "targets": [],
            "reason": "cluster_not_found",
        }

    datastores = list(cluster.get("datastores", []) or [])
    vm = _find_vm(vms, vm_id)
    if vm is None:
        return {
            "cluster_id": cluster_id,
            "cluster_name": cluster.get("name"),
            "vm_id": vm_id,
            "vm_name": None,
            "source_datastore_id": source_datastore_id,
            "source_datastore_name": None,
            "vm_size_gb": None,
            "policy": policy,
            "targets": [],
            "reason": "vm_not_found",
        }

    resolved_source_id = source_datastore_id or vm.get("home_datastore_id")
    source_ds = _find_datastore(datastores, str(resolved_source_id or ""))
    if source_ds is None:
        return {
            "cluster_id": cluster_id,
            "cluster_name": cluster.get("name"),
            "vm_id": vm.get("vm_id"),
            "vm_name": vm.get("vm_name"),
            "source_datastore_id": resolved_source_id,
            "source_datastore_name": None,
            "vm_size_gb": vm.get("size_gb"),
            "policy": policy,
            "targets": [],
            "reason": "source_datastore_not_found",
        }

    vm_size_gb = vm.get("size_gb")
    vm_size_bytes = _to_float(vm_size_gb, 0.0) * GB
    if vm_size_bytes <= 0:
        return {
            "cluster_id": cluster_id,
            "cluster_name": cluster.get("name"),
            "vm_id": vm.get("vm_id"),
            "vm_name": vm.get("vm_name"),
            "source_datastore_id": source_ds.get("id"),
            "source_datastore_name": source_ds.get("name"),
            "vm_size_gb": vm_size_gb,
            "policy": policy,
            "targets": [],
            "reason": "vm_size_unavailable",
        }

    source_capacity = _to_float(source_ds.get("_capacity_bytes"), 0.0)
    source_free = _to_float(source_ds.get("_free_bytes"), 0.0)
    source_projected_free = source_free + vm_size_bytes

    targets: list[dict[str, Any]] = []
    for target_ds in datastores:
        if target_ds.get("id") == source_ds.get("id"):
            continue

        target_capacity = _to_float(target_ds.get("_capacity_bytes"), 0.0)
        target_free = _to_float(target_ds.get("_free_bytes"), 0.0)

        compatible, reasons, projected_free, projected_free_pct, projected_used_pct = _compatibility(
            target_capacity,
            target_free,
            vm_size_bytes,
            policy,
        )

        if not bool(target_ds.get("accessible", True)):
            compatible = False
            if "insufficient_free_space_with_reserve" not in reasons:
                reasons.append("insufficient_free_space_with_reserve")

        targets.append(
            {
                "datastore_id": target_ds.get("id"),
                "datastore_name": target_ds.get("name"),
                "current_free_gb": target_ds.get("free_gb"),
                "current_used_pct": target_ds.get("used_pct"),
                "projected_free_gb": _to_gb(projected_free),
                "projected_free_pct": projected_free_pct,
                "projected_used_pct": projected_used_pct,
                "compatible": compatible,
                "reasons": reasons,
            }
        )

    targets.sort(
        key=lambda item: (
            0 if item.get("compatible") else 1,
            _to_float(item.get("projected_used_pct"), 999.0),
            str(item.get("datastore_name") or ""),
        )
    )

    return {
        "cluster_id": cluster_id,
        "cluster_name": cluster.get("name"),
        "vm_id": vm.get("vm_id"),
        "vm_name": vm.get("vm_name"),
        "vm_power_state": vm.get("power_state"),
        "vm_size_gb": vm_size_gb,
        "source_datastore_id": source_ds.get("id"),
        "source_datastore_name": source_ds.get("name"),
        "source_current_free_gb": source_ds.get("free_gb"),
        "source_current_used_pct": source_ds.get("used_pct"),
        "source_projected_free_gb": _to_gb(source_projected_free),
        "source_projected_used_pct": _calc_used_pct(source_capacity, source_projected_free),
        "policy": policy,
        "targets": targets,
        "reason": "ok",
    }


def _move_vm_sync(client: VCenterClient, cluster_id: str, vm_id: str, target_datastore_id: str, source_datastore_id: str | None = None) -> dict[str, Any]:
    with _service_instance(client) as si:
        content = si.RetrieveContent()

        with _view(content, [vim.StoragePod]) as pod_view:
            cluster_obj = next((obj for obj in pod_view if getattr(obj, "_moId", None) == cluster_id), None)
        if cluster_obj is None:
            raise SDRSOperationError("Datastore cluster não encontrado.")
        if not _is_allowed_pool_name(str(getattr(cluster_obj, "name", "") or "")):
            raise SDRSOperationError("Datastore cluster fora da política permitida.")

        cluster_name = str(getattr(cluster_obj, "name", "") or "")
        cluster_datastores: dict[str, Any] = {}
        for child in list(getattr(cluster_obj, "childEntity", []) or []):
            if isinstance(child, vim.Datastore):
                ds_id = getattr(child, "_moId", None)
                if ds_id:
                    cluster_datastores[str(ds_id)] = child

        with _view(content, [vim.VirtualMachine]) as vm_view:
            vm_obj = next((obj for obj in vm_view if getattr(obj, "_moId", None) == vm_id), None)
        if vm_obj is None:
            raise SDRSOperationError("VM não encontrada.")

        target_ds = cluster_datastores.get(str(target_datastore_id))
        source_ds = cluster_datastores.get(str(source_datastore_id)) if source_datastore_id else None

        current_ds = _primary_vm_datastore(vm_obj)
        current_ds_id = str(getattr(current_ds, "_moId", "") or "")

        if source_ds is None:
            source_ds = current_ds

        if source_ds is None:
            raise SDRSOperationError("Datastore de origem da VM não identificado.")
        if target_ds is None:
            raise SDRSOperationError("Datastore de destino não encontrado no cluster/pool selecionado.")

        if source_datastore_id and str(getattr(source_ds, "_moId", "")) not in cluster_datastores:
            raise SDRSOperationError("Datastore de origem não pertence ao cluster/pool selecionado.")

        if source_datastore_id and current_ds_id != str(source_datastore_id):
            raise SDRSOperationError("Datastore de origem informado não corresponde à VM selecionada.")

        if not source_datastore_id and current_ds_id not in cluster_datastores:
            raise SDRSOperationError("VM não está em datastore pertencente ao cluster/pool selecionado.")

        if getattr(source_ds, "_moId", None) == getattr(target_ds, "_moId", None):
            raise SDRSOperationError("Datastore de destino deve ser diferente do datastore de origem.")

        target_summary = getattr(target_ds, "summary", None)
        if not bool(getattr(target_summary, "accessible", True)):
            raise SDRSOperationError("Datastore de destino não está acessível.")

        vm_size_bytes = _estimate_vm_size_bytes(vm_obj)
        if vm_size_bytes is not None and vm_size_bytes > 0:
            target_free_bytes = _to_float(getattr(target_summary, "freeSpace", None), 0.0)
            if target_free_bytes < float(vm_size_bytes):
                raise SDRSOperationError("Espaço livre insuficiente no datastore de destino para a VM selecionada.")

        _enforce_storage_relocate_only(vm_obj)

        relocate_spec = vim.VirtualMachineRelocateSpec(datastore=target_ds)

        try:
            task = vm_obj.RelocateVM_Task(
                spec=relocate_spec,
                priority=vim.VirtualMachine.MovePriority.defaultPriority,
            )
        except Exception as exc:
            raise SDRSOperationError(f"Falha ao disparar RelocateVM_Task: {exc}") from exc

        _invalidate_inventory_cache(client)

        return {
            "cluster_id": cluster_id,
            "cluster_name": cluster_name,
            "vm_id": vm_id,
            "vm_name": getattr(vm_obj, "name", None),
            "source_datastore_id": getattr(source_ds, "_moId", None),
            "source_datastore_name": getattr(source_ds, "name", None),
            "target_datastore_id": getattr(target_ds, "_moId", None),
            "target_datastore_name": getattr(target_ds, "name", None),
            "task_id": getattr(task, "_moId", None),
            "state": "queued",
            "message": "Storage vMotion enfileirada com sucesso.",
            "reason": "ok",
        }


def _task_status_sync(client: VCenterClient, task_id: str) -> dict[str, Any]:
    with _service_instance(client) as si:
        content = si.RetrieveContent()
        task = _find_task(content, task_id)
        if task is None:
            return {"task_id": task_id, "found": False, "reason": "task_not_found"}

        info = getattr(task, "info", None)
        progress = getattr(info, "progress", None)
        try:
            progress_value = int(progress) if progress is not None else None
        except Exception:
            progress_value = None

        error_obj = getattr(info, "error", None)
        error_message = None
        if error_obj is not None:
            error_message = str(getattr(error_obj, "localizedMessage", None) or str(error_obj))

        return {
            "task_id": task_id,
            "found": True,
            "state": _normalize_task_state(getattr(info, "state", None)),
            "progress": progress_value,
            "error": error_message,
            "description": str(getattr(getattr(info, "description", None), "message", "") or ""),
            "entity_name": str(getattr(info, "entityName", "") or ""),
            "queue_time": _to_iso_or_none(getattr(info, "queueTime", None)),
            "start_time": _to_iso_or_none(getattr(info, "startTime", None)),
            "complete_time": _to_iso_or_none(getattr(info, "completeTime", None)),
            "result": None,
            "reason": "ok",
        }

async def list_vms(client: VCenterClient) -> list[dict[str, Any]]:
    _, vms = await asyncio.to_thread(_inventory_sync, client)
    return [
        {
            "vm_id": vm.get("vm_id"),
            "vm_name": vm.get("vm_name"),
            "size_gb": vm.get("size_gb"),
            "power_state": vm.get("power_state"),
            "home_datastore": vm.get("home_datastore"),
            "home_datastore_id": vm.get("home_datastore_id"),
        }
        for vm in vms
    ]


async def list_datastores(client: VCenterClient) -> list[dict[str, Any]]:
    clusters = await asyncio.to_thread(_cluster_inventory_sync, client)
    datastores: list[dict[str, Any]] = []
    seen: set[str] = set()
    for cluster in clusters.values():
        for ds in list(cluster.get("datastores", []) or []):
            ds_id = str(ds.get("moref_id") or ds.get("id") or "")
            if not ds_id or ds_id in seen:
                continue
            seen.add(ds_id)
            datastores.append(ds)
    datastores.sort(key=lambda item: str(item.get("name") or "").lower())
    return [
        {
            "moref_id": ds.get("moref_id"),
            "name": ds.get("name"),
            "capacity_gb": ds.get("capacity_gb"),
            "provisioned_gb": ds.get("provisioned_gb"),
            "free_gb": ds.get("free_gb"),
        }
        for ds in datastores
    ]


async def list_clusters(client: VCenterClient) -> list[dict[str, Any]]:
    try:
        return await asyncio.to_thread(_list_clusters_sync, client)
    except Exception:
        logger.exception("Erro ao listar clusters em modo manual")
        return []


async def get_cluster_detail(client: VCenterClient, cluster_id: str) -> dict[str, Any]:
    try:
        return await asyncio.to_thread(_get_cluster_detail_sync, client, cluster_id)
    except Exception:
        logger.exception("Erro ao obter detalhe do cluster %s", cluster_id)
        return {}


async def get_pending_recommendations(client: VCenterClient, cluster_id: str) -> list[dict[str, Any]]:
    try:
        return await asyncio.to_thread(_get_pending_recommendations_sync, client, cluster_id)
    except Exception:
        logger.exception("Erro ao obter recomendações pendentes do cluster %s", cluster_id)
        return []


async def get_move_candidates(client: VCenterClient, cluster_id: str, limit: int = 20) -> dict[str, Any]:
    safe_limit = max(1, min(int(limit), 50))
    try:
        return await asyncio.to_thread(_build_move_candidates_sync, client, cluster_id, safe_limit)
    except Exception:
        logger.exception("Erro ao obter candidatos do cluster %s", cluster_id)
        return {
            "cluster_id": cluster_id,
            "cluster_name": None,
            "policy": _move_policy(),
            "items": [],
            "reason": "unexpected_error",
        }


async def get_simulated_move_plan(client: VCenterClient, cluster_id: str, max_moves: int = 3) -> dict[str, Any]:
    safe_max = max(1, min(int(max_moves), 10))
    try:
        return await asyncio.to_thread(_build_simulated_plan_sync, client, cluster_id, safe_max)
    except Exception:
        logger.exception("Erro ao simular plano do cluster %s", cluster_id)
        return {
            "cluster_id": cluster_id,
            "cluster_name": None,
            "max_moves": safe_max,
            "policy": _move_policy(),
            "before": {"avg_used_pct": 0.0, "space_imbalance_pct": 0.0},
            "after": {"avg_used_pct": 0.0, "space_imbalance_pct": 0.0},
            "delta": {"avg_used_pct_delta": 0.0, "space_imbalance_pct_delta": 0.0},
            "source_candidates": 0,
            "items": [],
            "reason": "unexpected_error",
        }


async def diagnose_latency_collection(client: VCenterClient, cluster_id: str | None = None, max_datastores_per_cluster: int = 3) -> dict[str, Any]:
    try:
        return await asyncio.to_thread(_diagnose_latency_collection_sync, client, cluster_id, max_datastores_per_cluster)
    except Exception:
        logger.exception("Erro no diagnóstico de latência")
        return {
            "host": client.host,
            "cluster_filter": cluster_id,
            "message": "Latency diagnostics disabled in manual migration mode.",
            "clusters": [],
        }


async def list_datastore_vms(client: VCenterClient, cluster_id: str, datastore_id: str) -> dict[str, Any]:
    try:
        return await asyncio.to_thread(_list_datastore_vms_sync, client, cluster_id, datastore_id)
    except Exception:
        logger.exception("Erro ao listar VMs do datastore %s", datastore_id)
        return {
            "cluster_id": cluster_id,
            "cluster_name": None,
            "datastore_id": datastore_id,
            "datastore_name": None,
            "items": [],
            "reason": "unexpected_error",
        }


async def move_vm_to_datastore(
    client: VCenterClient,
    cluster_id: str,
    vm_id: str,
    target_datastore_id: str,
    source_datastore_id: str | None = None,
) -> dict[str, Any]:
    try:
        return await asyncio.to_thread(_move_vm_sync, client, cluster_id, vm_id, target_datastore_id, source_datastore_id)
    except SDRSOperationError:
        raise
    except Exception as exc:
        logger.exception("Erro inesperado ao mover VM vm_id=%s", vm_id)
        raise SDRSOperationError(f"Erro inesperado ao solicitar migração da VM: {exc}") from exc


async def get_move_options_for_vm(
    client: VCenterClient,
    cluster_id: str,
    vm_id: str,
    source_datastore_id: str | None = None,
) -> dict[str, Any]:
    try:
        return await asyncio.to_thread(_move_options_for_vm_sync, client, cluster_id, vm_id, source_datastore_id)
    except Exception:
        logger.exception("Erro ao obter opções de move vm_id=%s", vm_id)
        return {
            "cluster_id": cluster_id,
            "cluster_name": None,
            "vm_id": vm_id,
            "vm_name": None,
            "source_datastore_id": source_datastore_id,
            "source_datastore_name": None,
            "vm_size_gb": None,
            "policy": _move_policy(),
            "targets": [],
            "reason": "unexpected_error",
        }


async def get_task_status(client: VCenterClient, task_id: str) -> dict[str, Any]:
    try:
        return await asyncio.to_thread(_task_status_sync, client, task_id)
    except Exception:
        logger.exception("Erro ao obter status da task %s", task_id)
        return {
            "task_id": task_id,
            "found": False,
            "reason": "unexpected_error",
        }
