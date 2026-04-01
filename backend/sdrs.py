from __future__ import annotations

import asyncio
import logging
import os
import ssl
from contextlib import contextmanager
from typing import Any, Iterator

from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim

from vcenter import VCenterClient

logger = logging.getLogger("sdrs-manager.sdrs")

GB = 1024 ** 3
_PERF_COUNTER_LATENCY_READ_CANDIDATES = (
    ("datastore", "totalReadLatency", "average"),
    ("datastore", "readLatency", "average"),
)
_PERF_COUNTER_LATENCY_WRITE_CANDIDATES = (
    ("datastore", "totalWriteLatency", "average"),
    ("datastore", "writeLatency", "average"),
)


class SDRSOperationError(Exception):
    """Erro controlado para operações SDRS (leitura e ações manuais)."""


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


def _enforce_storage_relocate_only(vm_obj: Any) -> None:
    """
    Guardrail de segurança:
    esta aplicação só pode disparar Storage vMotion (RelocateVM_Task).
    """
    if vm_obj is None:
        raise SDRSOperationError("VM inválida para operação de migração.")

    if not hasattr(vm_obj, "RelocateVM_Task"):
        raise SDRSOperationError("VM não suporta operação de RelocateVM_Task.")


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


def _get_move_policy() -> dict[str, float | int]:
    return {
        "min_free_headroom_pct": _env_float("MOVE_MIN_FREE_HEADROOM_PCT", default=15.0, min_value=2.0, max_value=40.0),
        "min_vm_reserve_ratio": _env_float("MOVE_MIN_VM_RESERVE_RATIO", default=0.10, min_value=0.0, max_value=1.0),
        "max_target_used_pct": _env_float("MOVE_MAX_TARGET_USED_PCT", default=95.0, min_value=70.0, max_value=99.5),
        "max_concurrent_per_cluster": _env_int("MOVE_MAX_CONCURRENT_PER_CLUSTER", default=2, min_value=1, max_value=20),
    }


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
            # pyVmomi pode retornar tipos array-like (ex.: double[])
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


def _to_gb(value: Any) -> float | None:
    try:
        if value is None:
            return None
        return round(float(value) / GB, 2)
    except Exception:
        return None


def _to_used_pct(capacity: Any, free_space: Any) -> float | None:
    try:
        if capacity in (None, 0):
            return None
        used = float(capacity) - float(free_space or 0)
        return round((used / float(capacity)) * 100.0, 2)
    except Exception:
        return None


def _normalize_behavior(enabled: bool, raw_behavior: Any) -> str:
    if not enabled:
        return "Disabled"

    behavior = str(raw_behavior or "").strip().lower()

    if "auto" in behavior or "fully" in behavior:
        return "Automated"

    if "manual" in behavior:
        return "Manual"

    # Fallback seguro quando o cluster está enabled mas a enum não veio clara.
    return "Manual"


def _extract_free_space_threshold_gb(pod_config: Any) -> int | None:
    space_cfg = _safe_get(pod_config, "spaceLoadBalanceConfig")
    value = _safe_get(
        space_cfg,
        "freeSpaceThresholdGB",
        "freeSpaceThresholdGb",
        default=None,
    )

    try:
        return int(value) if value is not None else None
    except Exception:
        return None


def _extract_io_latency_threshold(pod_config: Any) -> int | None:
    """
    Best effort.

    Em alguns ambientes/versões esse valor pode não estar disponível diretamente
    no pod config. Tentamos alguns nomes possíveis e, se não existir, retornamos None.
    """
    io_cfg = _safe_get(pod_config, "ioLoadBalanceConfig")
    candidates = (
        _safe_get(io_cfg, "ioLatencyThreshold"),
        _safe_get(io_cfg, "latencyThreshold"),
        _safe_get(io_cfg, "congestionThreshold"),
        _safe_get(io_cfg, "reservableIopsThreshold"),
    )

    for value in candidates:
        try:
            if value is not None:
                return int(value)
        except Exception:
            continue

    return None


@contextmanager
def _service_instance(client: VCenterClient) -> Iterator[Any]:
    si = None
    try:
        ssl_context = ssl.create_default_context()
        if not client.verify_ssl:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        si = SmartConnect(
            host=client.host,
            user=client.user,
            pwd=client.password,
            sslContext=ssl_context,
        )

        yield si

    finally:
        if si:
            try:
                Disconnect(si)
            except Exception:
                logger.exception("Erro ao desconectar sessão pyVmomi do vCenter host=%s", client.host)


def _get_storage_pods(content: Any) -> list[Any]:
    view = None
    try:
        view = content.viewManager.CreateContainerView(
            content.rootFolder,
            [vim.StoragePod],
            True,
        )
        return list(view.view or [])
    finally:
        if view:
            try:
                view.Destroy()
            except Exception:
                logger.debug("Falha ao destruir ContainerView de StoragePod", exc_info=True)


def _find_storage_pod(content: Any, cluster_id: str) -> Any | None:
    for pod in _get_storage_pods(content):
        if getattr(pod, "_moId", None) == cluster_id:
            return pod
    return None


def _get_member_datastores(pod: Any) -> list[Any]:
    datastores: list[Any] = []

    try:
        for child in list(getattr(pod, "childEntity", []) or []):
            if isinstance(child, vim.Datastore):
                datastores.append(child)
    except Exception:
        logger.exception("Erro ao listar membros do datastore cluster %s", getattr(pod, "name", "unknown"))

    return datastores


def _extract_pod_config(pod: Any) -> dict[str, Any]:
    entry = _safe_get(pod, "podStorageDrsEntry")
    sdrs_config = _safe_get(entry, "storageDrsConfig")
    pod_config = _safe_get(sdrs_config, "podConfig")

    enabled = bool(_safe_get(pod_config, "enabled", default=False))
    raw_behavior = _safe_get(pod_config, "defaultVmBehavior")
    automation_level = _normalize_behavior(enabled, raw_behavior)

    return {
        "sdrs_enabled": enabled,
        "sdrs_automation_level": automation_level,
        "free_space_threshold": _extract_free_space_threshold_gb(pod_config),
        "io_latency_threshold": _extract_io_latency_threshold(pod_config),
    }


def _build_perf_counter_index(content: Any) -> dict[tuple[str, str, str], int]:
    perf_manager = getattr(content, "perfManager", None)
    if perf_manager is None:
        return {}

    counters = list(getattr(perf_manager, "perfCounter", []) or [])
    index: dict[tuple[str, str, str], int] = {}

    for counter in counters:
        try:
            group_key = str(_safe_get(_safe_get(counter, "groupInfo"), "key", default="") or "").strip()
            name_key = str(_safe_get(_safe_get(counter, "nameInfo"), "key", default="") or "").strip()
            rollup = str(_safe_get(counter, "rollupType", default="") or "").strip()
            key = int(_safe_get(counter, "key", default=0) or 0)

            if not group_key or not name_key or not rollup or key <= 0:
                continue

            index[(group_key, name_key, rollup)] = key
        except Exception:
            continue

    return index


def _resolve_latency_counter_ids(
    perf_counter_index: dict[tuple[str, str, str], int],
) -> tuple[list[int], list[int]]:
    read_ids: list[int] = []
    write_ids: list[int] = []

    for candidate in _PERF_COUNTER_LATENCY_READ_CANDIDATES:
        counter_id = perf_counter_index.get(candidate)
        if counter_id and counter_id not in read_ids:
            read_ids.append(counter_id)

    for candidate in _PERF_COUNTER_LATENCY_WRITE_CANDIDATES:
        counter_id = perf_counter_index.get(candidate)
        if counter_id and counter_id not in write_ids:
            write_ids.append(counter_id)

    return read_ids, write_ids


def _query_available_perf_metrics(perf_manager: Any, datastore: Any) -> tuple[list[Any], str, str | None]:
    method = getattr(perf_manager, "QueryAvailablePerfMetric", None)
    label = "QueryAvailablePerfMetric"
    if method is None:
        method = getattr(perf_manager, "QueryAvailableMetric", None)
        label = "QueryAvailableMetric"

    if method is None:
        return [], "unavailable", "Método de métricas disponíveis não encontrado."

    # Algumas versões aceitam apenas intervalId; outras aceitam sem args extras.
    strategies = (
        {"intervalId": 20},
        {},
    )
    first_err: str | None = None

    for kwargs in strategies:
        try:
            available = method(entity=datastore, **kwargs)
            mode = "ok(interval=20)" if kwargs else "ok(no-interval)"
            return list(available or []), f"{label}:{mode}", None
        except Exception as exc:
            if first_err is None:
                first_err = _format_exc(exc)
            continue

    return [], f"{label}:error", first_err


def _query_perf_values_for_counters(
    content: Any,
    datastore: Any,
    counter_ids: list[int],
) -> dict[int, list[float]]:
    perf_manager = getattr(content, "perfManager", None)
    if perf_manager is None or not counter_ids:
        return {}

    available_counter_ids: set[int] = set()
    available, available_mode, _ = _query_available_perf_metrics(perf_manager, datastore)
    available_call_failed = str(available_mode).endswith(":error")

    for metric in list(available or []):
        try:
            counter_id = _safe_get(metric, "counterId")
            if counter_id is not None:
                available_counter_ids.add(int(counter_id))
        except Exception:
            continue

    selected_counter_ids = (
        counter_ids
        if available_call_failed or not available_counter_ids
        else [counter_id for counter_id in counter_ids if counter_id in available_counter_ids]
    )
    if not selected_counter_ids:
        return {}

    metric_ids = [
        vim.PerformanceManager.MetricId(counterId=counter_id, instance="*")
        for counter_id in selected_counter_ids
    ]

    query_spec = vim.PerformanceManager.QuerySpec(
        entity=datastore,
        metricId=metric_ids,
        intervalId=20,
        maxSample=1,
    )

    try:
        series = perf_manager.QueryPerf(querySpec=[query_spec])
    except Exception:
        # Fallback sem intervalId para ambientes que não aceitam realtime nesse objeto.
        query_spec = vim.PerformanceManager.QuerySpec(
            entity=datastore,
            metricId=metric_ids,
            maxSample=1,
        )
        series = perf_manager.QueryPerf(querySpec=[query_spec])

    values_by_counter: dict[int, list[float]] = {}
    for item in list(series or []):
        for metric in list(_safe_get(item, "value", default=[]) or []):
            counter_id = _safe_get(_safe_get(metric, "id"), "counterId")
            if counter_id is None:
                continue

            numeric_values: list[float] = []
            for value in list(_safe_get(metric, "value", default=[]) or []):
                try:
                    numeric_values.append(float(value))
                except Exception:
                    continue

            if numeric_values:
                values_by_counter.setdefault(int(counter_id), []).extend(numeric_values)

    return values_by_counter


def _extract_latency_from_perf_manager(
    content: Any,
    datastore: Any,
    perf_counter_index: dict[tuple[str, str, str], int] | None = None,
) -> float | None:
    try:
        index = perf_counter_index if perf_counter_index is not None else _build_perf_counter_index(content)
        if not index:
            return None

        read_ids, write_ids = _resolve_latency_counter_ids(index)
        ordered_ids: list[int] = []
        for counter_id in [*read_ids, *write_ids]:
            if counter_id not in ordered_ids:
                ordered_ids.append(counter_id)

        if not ordered_ids:
            return None

        values_by_counter = _query_perf_values_for_counters(content, datastore, ordered_ids)
        if not values_by_counter:
            return None

        def avg_for(counter_ids: list[int]) -> float | None:
            numeric: list[float] = []
            for counter_id in counter_ids:
                numeric.extend(values_by_counter.get(counter_id, []))
            if not numeric:
                return None
            return round(sum(numeric) / len(numeric), 2)

        read_latency = avg_for(read_ids)
        write_latency = avg_for(write_ids)
        dual = [value for value in (read_latency, write_latency) if value is not None]

        if dual:
            return round(sum(dual) / len(dual), 2)

        merged: list[float] = []
        for values in values_by_counter.values():
            merged.extend(values)

        if merged:
            return round(sum(merged) / len(merged), 2)

        return None

    except Exception:
        logger.debug(
            "Fallback de latência via PerformanceManager falhou para datastore %s",
            getattr(datastore, "name", "unknown"),
            exc_info=True,
        )
        return None


def _extract_latency_from_perf_summary(
    content: Any,
    datastore: Any,
    perf_counter_index: dict[tuple[str, str, str], int] | None = None,
) -> float | None:
    """
    Best effort para latência por datastore.

    QueryDatastorePerformanceSummary pode não existir ou falhar dependendo da versão /
    permissões / tipo do datastore. Nesse caso retornamos None.
    """
    try:
        srm = getattr(content, "storageResourceManager", None)
        if not srm or not hasattr(srm, "QueryDatastorePerformanceSummary"):
            return _extract_latency_from_perf_manager(content, datastore, perf_counter_index=perf_counter_index)

        summaries = None
        # Em vários ambientes pyVmomi, o parâmetro esperado é lista de datastores.
        try:
            summaries = srm.QueryDatastorePerformanceSummary(datastore=[datastore])
        except TypeError:
            summaries = srm.QueryDatastorePerformanceSummary(datastore=datastore)

        if not summaries:
            return _extract_latency_from_perf_manager(content, datastore, perf_counter_index=perf_counter_index)

        items = summaries if isinstance(summaries, list) else [summaries]
        summary = items[0] if items else None
        if summary is None:
            return _extract_latency_from_perf_manager(content, datastore, perf_counter_index=perf_counter_index)

        vm_latency = _mean_or_none(_safe_get(summary, "datastoreVmLatency", "vmLatency", "overallLatency"))
        read_latency = _mean_or_none(_safe_get(summary, "datastoreReadLatency", "readLatency"))
        write_latency = _mean_or_none(_safe_get(summary, "datastoreWriteLatency", "writeLatency"))

        if vm_latency is not None:
            return vm_latency

        numeric = [value for value in (read_latency, write_latency) if value is not None]

        if numeric:
            return round(sum(numeric) / len(numeric), 2)

        return _extract_latency_from_perf_manager(content, datastore, perf_counter_index=perf_counter_index)

    except Exception:
        logger.debug(
            "Não foi possível coletar latência via StorageResourceManager do datastore %s",
            getattr(datastore, "name", "unknown"),
            exc_info=True,
        )
        return _extract_latency_from_perf_manager(content, datastore, perf_counter_index=perf_counter_index)


def _format_exc(exc: Exception) -> str:
    return f"{type(exc).__name__}: {exc}"


def _extract_latency_from_srm_only(content: Any, datastore: Any) -> tuple[float | None, str | None]:
    try:
        srm = getattr(content, "storageResourceManager", None)
        if not srm or not hasattr(srm, "QueryDatastorePerformanceSummary"):
            return None, "QueryDatastorePerformanceSummary indisponível"

        try:
            summaries = srm.QueryDatastorePerformanceSummary(datastore=[datastore])
        except TypeError:
            summaries = srm.QueryDatastorePerformanceSummary(datastore=datastore)

        if not summaries:
            return None, "Summary vazio"

        items = summaries if isinstance(summaries, list) else [summaries]
        summary = items[0] if items else None
        if summary is None:
            return None, "Summary nulo"

        vm_latency = _mean_or_none(_safe_get(summary, "datastoreVmLatency", "vmLatency", "overallLatency"))
        read_latency = _mean_or_none(_safe_get(summary, "datastoreReadLatency", "readLatency"))
        write_latency = _mean_or_none(_safe_get(summary, "datastoreWriteLatency", "writeLatency"))

        if vm_latency is not None:
            return vm_latency, None

        numeric = [value for value in (read_latency, write_latency) if value is not None]

        if numeric:
            return round(sum(numeric) / len(numeric), 2), None

        return None, "Summary sem campos numéricos de latência"

    except Exception as exc:
        return None, _format_exc(exc)


def _diagnose_perf_manager_for_datastore(
    content: Any,
    datastore: Any,
    read_ids: list[int],
    write_ids: list[int],
) -> dict[str, Any]:
    diagnostic: dict[str, Any] = {
        "available_metric_call": "not-run",
        "available_metric_error": None,
        "available_metric_count": 0,
        "available_latency_counter_ids": [],
        "query_perf_call": "not-run",
        "query_perf_error": None,
        "query_perf_value_count": 0,
        "query_perf_latency_ms": None,
    }

    perf_manager = getattr(content, "perfManager", None)
    if perf_manager is None:
        diagnostic["available_metric_call"] = "unavailable"
        diagnostic["query_perf_call"] = "unavailable"
        return diagnostic

    all_latency_ids = [*read_ids, *write_ids]
    dedup_latency_ids: list[int] = []
    for counter_id in all_latency_ids:
        if counter_id not in dedup_latency_ids:
            dedup_latency_ids.append(counter_id)

    available_counter_ids: set[int] = set()
    available, available_mode, available_err = _query_available_perf_metrics(perf_manager, datastore)
    available_call_failed = str(available_mode).endswith(":error")
    diagnostic["available_metric_call"] = available_mode
    diagnostic["available_metric_error"] = available_err

    for metric in list(available or []):
        try:
            counter_id = _safe_get(metric, "counterId")
            if counter_id is not None:
                available_counter_ids.add(int(counter_id))
        except Exception:
            continue

    diagnostic["available_metric_count"] = len(available_counter_ids)

    selected_counter_ids = (
        dedup_latency_ids
        if available_call_failed or not available_counter_ids
        else [counter_id for counter_id in dedup_latency_ids if counter_id in available_counter_ids]
    )
    diagnostic["available_latency_counter_ids"] = selected_counter_ids

    if not selected_counter_ids:
        diagnostic["query_perf_call"] = "skipped(no-latency-counters-available)"
        return diagnostic

    metric_ids = [
        vim.PerformanceManager.MetricId(counterId=counter_id, instance="*")
        for counter_id in selected_counter_ids
    ]

    query_spec = vim.PerformanceManager.QuerySpec(
        entity=datastore,
        metricId=metric_ids,
        intervalId=20,
        maxSample=1,
    )

    try:
        series = perf_manager.QueryPerf(querySpec=[query_spec])
        diagnostic["query_perf_call"] = "ok(interval=20)"
    except Exception as exc:
        try:
            query_spec = vim.PerformanceManager.QuerySpec(
                entity=datastore,
                metricId=metric_ids,
                maxSample=1,
            )
            series = perf_manager.QueryPerf(querySpec=[query_spec])
            diagnostic["query_perf_call"] = "ok(no-interval)"
        except Exception as exc2:
            series = []
            diagnostic["query_perf_call"] = "error"
            diagnostic["query_perf_error"] = f"{_format_exc(exc)} | fallback: {_format_exc(exc2)}"
            return diagnostic

    values_by_counter: dict[int, list[float]] = {}
    for item in list(series or []):
        for metric in list(_safe_get(item, "value", default=[]) or []):
            counter_id = _safe_get(_safe_get(metric, "id"), "counterId")
            if counter_id is None:
                continue

            numeric_values: list[float] = []
            for value in list(_safe_get(metric, "value", default=[]) or []):
                try:
                    numeric_values.append(float(value))
                except Exception:
                    continue

            if numeric_values:
                values_by_counter.setdefault(int(counter_id), []).extend(numeric_values)

    merged: list[float] = []
    for values in values_by_counter.values():
        merged.extend(values)

    diagnostic["query_perf_value_count"] = len(merged)
    if merged:
        diagnostic["query_perf_latency_ms"] = round(sum(merged) / len(merged), 2)

    return diagnostic


def _diagnose_latency_collection_sync(
    client: VCenterClient,
    cluster_id: str | None = None,
    max_datastores_per_cluster: int = 3,
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "host": client.host,
        "cluster_filter": cluster_id,
        "perf_manager_available": False,
        "storage_resource_manager_available": False,
        "latency_counter_candidates": {
            "read": list(_PERF_COUNTER_LATENCY_READ_CANDIDATES),
            "write": list(_PERF_COUNTER_LATENCY_WRITE_CANDIDATES),
        },
        "clusters": [],
    }

    with _service_instance(client) as si:
        content = si.RetrieveContent()

        report["perf_manager_available"] = getattr(content, "perfManager", None) is not None
        srm = getattr(content, "storageResourceManager", None)
        report["storage_resource_manager_available"] = bool(
            srm and hasattr(srm, "QueryDatastorePerformanceSummary")
        )

        perf_counter_index = _build_perf_counter_index(content)
        read_ids, write_ids = _resolve_latency_counter_ids(perf_counter_index)
        report["latency_counter_ids"] = {
            "read": read_ids,
            "write": write_ids,
        }
        report["perf_counter_index_size"] = len(perf_counter_index)

        pods = _get_storage_pods(content)
        if cluster_id:
            pods = [pod for pod in pods if getattr(pod, "_moId", None) == cluster_id]

        for pod in pods:
            datastores = _get_member_datastores(pod)

            nonnull = 0
            for ds in datastores:
                latency = _extract_latency_from_perf_summary(
                    content,
                    ds,
                    perf_counter_index=perf_counter_index,
                )
                if latency is not None:
                    nonnull += 1

            sample_items: list[dict[str, Any]] = []
            for ds in datastores[:max_datastores_per_cluster]:
                srm_latency, srm_error = _extract_latency_from_srm_only(content, ds)
                perf_diag = _diagnose_perf_manager_for_datastore(content, ds, read_ids, write_ids)

                sample_items.append(
                    {
                        "datastore_id": getattr(ds, "_moId", None),
                        "datastore_name": getattr(ds, "name", "unknown"),
                        "srm_latency_ms": srm_latency,
                        "srm_error": srm_error,
                        "perf": perf_diag,
                    }
                )

            report["clusters"].append(
                {
                    "cluster_id": getattr(pod, "_moId", None),
                    "cluster_name": getattr(pod, "name", "unknown"),
                    "datastore_count": len(datastores),
                    "latency_nonnull_count": nonnull,
                    "latency_null_count": len(datastores) - nonnull,
                    "sample_datastores": sample_items,
                }
            )

    return report


def _build_datastore_summary(
    content: Any,
    datastore: Any,
    perf_counter_index: dict[tuple[str, str, str], int] | None = None,
) -> dict[str, Any]:
    summary = _safe_get(datastore, "summary")
    capacity = _safe_get(summary, "capacity", default=0)
    free_space = _safe_get(summary, "freeSpace", default=0)

    return {
        "id": getattr(datastore, "_moId", None),
        "name": getattr(datastore, "name", "unknown"),
        "capacity_gb": _to_gb(capacity),
        "free_gb": _to_gb(free_space),
        "used_pct": _to_used_pct(capacity, free_space),
        "latency_ms": _extract_latency_from_perf_summary(
            content,
            datastore,
            perf_counter_index=perf_counter_index,
        ),
    }


def _object_name(obj: Any) -> str | None:
    try:
        return getattr(obj, "name", None)
    except Exception:
        return None


def _extract_vm_name_from_rec(rec: Any) -> str | None:
    vm = _safe_get(rec, "vm")
    if vm is not None:
        name = _object_name(vm)
        if name:
            return name

    for action in list(_safe_get(rec, "action", default=[]) or []):
        for attr in ("vm", "targetVm", "sourceVm", "target"):
            obj = _safe_get(action, attr)
            if obj is not None and isinstance(obj, vim.VirtualMachine):
                name = _object_name(obj)
                if name:
                    return name

    return None


def _extract_datastores_from_rec(rec: Any) -> tuple[str | None, str | None]:
    source_name: str | None = None
    target_name: str | None = None

    def maybe_set(obj: Any, current: str | None) -> str | None:
        if current:
            return current
        if obj is not None and isinstance(obj, vim.Datastore):
            return _object_name(obj)
        return current

    for action in list(_safe_get(rec, "action", default=[]) or []):
        source_name = maybe_set(_safe_get(action, "source"), source_name)
        source_name = maybe_set(_safe_get(action, "sourceDatastore"), source_name)
        source_name = maybe_set(_safe_get(action, "srcDatastore"), source_name)

        target_name = maybe_set(_safe_get(action, "destination"), target_name)
        target_name = maybe_set(_safe_get(action, "target"), target_name)
        target_name = maybe_set(_safe_get(action, "targetDatastore"), target_name)
        target_name = maybe_set(_safe_get(action, "destDatastore"), target_name)
        target_name = maybe_set(_safe_get(action, "destinationDatastore"), target_name)

    return source_name, target_name


def _extract_size_gb_from_rec(rec: Any) -> float | None:
    direct_candidates = [
        _safe_get(rec, "size"),
        _safe_get(rec, "sizeGb"),
        _safe_get(rec, "spaceUtil"),
        _safe_get(rec, "migrationSize"),
    ]

    for action in list(_safe_get(rec, "action", default=[]) or []):
        direct_candidates.extend(
            [
                _safe_get(action, "size"),
                _safe_get(action, "sizeGb"),
                _safe_get(action, "spaceUtil"),
                _safe_get(action, "migrationSize"),
                _safe_get(action, "diskSpaceToMove"),
            ]
        )

    for value in direct_candidates:
        try:
            if value is not None:
                numeric = float(value)
                # Se vier muito grande, assumimos bytes.
                if numeric > GB:
                    return round(numeric / GB, 2)
                return round(numeric, 2)
        except Exception:
            continue

    vm = _safe_get(rec, "vm")
    if vm is None:
        for action in list(_safe_get(rec, "action", default=[]) or []):
            candidate = _safe_get(action, "vm")
            if isinstance(candidate, vim.VirtualMachine):
                vm = candidate
                break

    try:
        if vm is not None:
            storage = _safe_get(_safe_get(vm, "summary"), "storage")
            committed = _safe_get(storage, "committed", default=0) or 0
            if committed:
                return _to_gb(committed)
    except Exception:
        logger.debug("Falha ao estimar size_gb pela VM da recomendação", exc_info=True)

    return None


def _extract_rec_type(rec: Any) -> str:
    reason = str(_safe_get(rec, "reason", default="") or "").strip()

    if reason:
        normalized = reason.lower()
        if "space" in normalized:
            return "SpaceBalance"
        if "io" in normalized or "latency" in normalized:
            return "IoBalance"
        return reason

    actions = list(_safe_get(rec, "action", default=[]) or [])
    if actions:
        return type(actions[0]).__name__

    return "Recommendation"


def _recommendation_to_dict(rec: Any) -> dict[str, Any]:
    source_ds, target_ds = _extract_datastores_from_rec(rec)

    return {
        "key": str(_safe_get(rec, "key", default="") or ""),
        "type": _extract_rec_type(rec),
        "reason": str(_safe_get(rec, "reason", default="") or ""),
        "source_ds": source_ds,
        "target_ds": target_ds,
        "vm_name": _extract_vm_name_from_rec(rec),
        "size_gb": _extract_size_gb_from_rec(rec),
    }


def _list_clusters_sync(client: VCenterClient) -> list[dict[str, Any]]:
    clusters: list[dict[str, Any]] = []

    with _service_instance(client) as si:
        content = si.RetrieveContent()

        for pod in _get_storage_pods(content):
            try:
                config = _extract_pod_config(pod)
                datastores = _get_member_datastores(pod)

                total_free_gb = 0.0
                for ds in datastores:
                    free_gb = _to_gb(_safe_get(_safe_get(ds, "summary"), "freeSpace", default=0))
                    if free_gb is not None:
                        total_free_gb += free_gb

                clusters.append(
                    {
                        "id": getattr(pod, "_moId", None),
                        "name": getattr(pod, "name", "unknown"),
                        "sdrs_enabled": config["sdrs_enabled"],
                        "sdrs_automation_level": config["sdrs_automation_level"],
                        "free_space_threshold": config["free_space_threshold"],
                        "io_latency_threshold": config["io_latency_threshold"],
                        "datastore_count": len(datastores),
                        "total_free_gb": round(total_free_gb, 2),
                    }
                )
            except Exception:
                logger.exception(
                    "Falha ao montar resumo do datastore cluster %s",
                    getattr(pod, "name", "unknown"),
                )

    return clusters


def _get_cluster_detail_sync(client: VCenterClient, cluster_id: str) -> dict[str, Any]:
    with _service_instance(client) as si:
        content = si.RetrieveContent()
        pod = _find_storage_pod(content, cluster_id)

        if pod is None:
            logger.warning("Datastore cluster não encontrado: %s", cluster_id)
            return {}

        config = _extract_pod_config(pod)
        datastores = _get_member_datastores(pod)
        perf_counter_index = _build_perf_counter_index(content)

        datastore_items: list[dict[str, Any]] = []
        for ds in datastores:
            try:
                datastore_items.append(
                    _build_datastore_summary(
                        content,
                        ds,
                        perf_counter_index=perf_counter_index,
                    )
                )
            except Exception:
                logger.exception(
                    "Falha ao montar detalhe do datastore %s no cluster %s",
                    getattr(ds, "name", "unknown"),
                    getattr(pod, "name", "unknown"),
                )

        return {
            "id": getattr(pod, "_moId", None),
            "name": getattr(pod, "name", "unknown"),
            "sdrs_enabled": config["sdrs_enabled"],
            "sdrs_automation_level": config["sdrs_automation_level"],
            "free_space_threshold": config["free_space_threshold"],
            "io_latency_threshold": config["io_latency_threshold"],
            "datastore_count": len(datastores),
            "datastores": datastore_items,
        }


def _get_pending_recommendations_sync(client: VCenterClient, cluster_id: str) -> list[dict[str, Any]]:
    with _service_instance(client) as si:
        content = si.RetrieveContent()
        pod = _find_storage_pod(content, cluster_id)

        if pod is None:
            logger.warning("Datastore cluster não encontrado para recomendações: %s", cluster_id)
            return []

        entry = _safe_get(pod, "podStorageDrsEntry")
        recommendations = list(_safe_get(entry, "recommendation", default=[]) or [])

        result: list[dict[str, Any]] = []
        for rec in recommendations:
            try:
                result.append(_recommendation_to_dict(rec))
            except Exception:
                logger.exception(
                    "Falha ao interpretar recomendação SDRS no cluster %s",
                    getattr(pod, "name", "unknown"),
                )

        return result


def _estimate_vm_size_gb(vm: Any) -> float | None:
    try:
        storage = _safe_get(_safe_get(vm, "summary"), "storage")
        committed = float(_safe_get(storage, "committed", default=0) or 0)
        uncommitted = float(_safe_get(storage, "uncommitted", default=0) or 0)
        total = committed + uncommitted
        if total <= 0:
            total = committed
        if total <= 0:
            return None
        return round(total / GB, 2)
    except Exception:
        return None


def _build_datastore_info_for_candidates(datastore: Any) -> dict[str, Any]:
    summary = _safe_get(datastore, "summary")
    capacity = float(_safe_get(summary, "capacity", default=0) or 0)
    free_space = float(_safe_get(summary, "freeSpace", default=0) or 0)
    used_pct = _to_used_pct(capacity, free_space)
    vm_count = len(list(getattr(datastore, "vm", []) or []))

    return {
        "obj": datastore,
        "id": getattr(datastore, "_moId", None),
        "name": getattr(datastore, "name", "unknown"),
        "capacity_bytes": capacity,
        "free_bytes": free_space,
        "used_pct": used_pct,
        "vm_count": vm_count,
    }


def _collect_source_vm_candidates(datastore: Any, max_vms: int = 8) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for vm in list(getattr(datastore, "vm", []) or []):
        try:
            size_gb = _estimate_vm_size_gb(vm)
            if size_gb is None or size_gb <= 1:
                continue
            result.append(
                {
                    "vm_obj": vm,
                    "vm_id": getattr(vm, "_moId", None),
                    "vm_name": getattr(vm, "name", "unknown"),
                    "size_gb": size_gb,
                    "size_bytes": size_gb * GB,
                }
            )
        except Exception:
            continue

    result.sort(key=lambda item: item["size_gb"], reverse=True)
    return result[:max_vms]


def _simulate_used_pct_after_move(info: dict[str, Any], move_size_bytes: float, is_source: bool) -> float | None:
    capacity = float(info.get("capacity_bytes", 0) or 0)
    free = float(info.get("free_bytes", 0) or 0)
    if capacity <= 0:
        return None

    if is_source:
        free_after = free + move_size_bytes
    else:
        free_after = free - move_size_bytes
    free_after = max(0.0, min(capacity, free_after))

    used_after = ((capacity - free_after) / capacity) * 100.0
    return round(used_after, 2)


def _build_move_candidates_sync(
    client: VCenterClient,
    cluster_id: str,
    limit: int = 20,
) -> dict[str, Any]:
    with _service_instance(client) as si:
        content = si.RetrieveContent()
        pod = _find_storage_pod(content, cluster_id)

        if pod is None:
            logger.warning("Datastore cluster não encontrado para candidatos: %s", cluster_id)
            return {
                "cluster_id": cluster_id,
                "cluster_name": None,
                "items": [],
                "reason": "cluster_not_found",
            }

        datastores = _get_member_datastores(pod)
        ds_infos = [_build_datastore_info_for_candidates(ds) for ds in datastores]
        ds_infos = [info for info in ds_infos if info.get("capacity_bytes", 0) > 0]

        if len(ds_infos) < 2:
            return {
                "cluster_id": getattr(pod, "_moId", None),
                "cluster_name": getattr(pod, "name", "unknown"),
                "items": [],
                "reason": "insufficient_datastores",
            }

        policy = _get_move_policy()
        used_values = [float(info["used_pct"]) for info in ds_infos if info.get("used_pct") is not None]
        avg_used = round(sum(used_values) / len(used_values), 2) if used_values else 0.0

        source_threshold = max(75.0, avg_used + 5.0)
        target_threshold = min(70.0, avg_used - 5.0)

        sources = [
            info
            for info in ds_infos
            if info.get("used_pct") is not None and float(info["used_pct"]) >= source_threshold and info["vm_count"] > 0
        ]
        targets = [
            info
            for info in ds_infos
            if info.get("used_pct") is not None and float(info["used_pct"]) <= target_threshold
        ]

        if not sources:
            return {
                "cluster_id": getattr(pod, "_moId", None),
                "cluster_name": getattr(pod, "name", "unknown"),
                "items": [],
                "reason": "no_source_pressure",
                "avg_used_pct": avg_used,
            }

        if not targets:
            targets = sorted(ds_infos, key=lambda info: float(info.get("used_pct") or 100.0))[:3]

        sources.sort(key=lambda info: float(info.get("used_pct") or 0), reverse=True)
        targets.sort(key=lambda info: float(info.get("used_pct") or 100))

        items: list[dict[str, Any]] = []
        seen_vm_ids: set[str] = set()

        for source in sources:
            vm_candidates = _collect_source_vm_candidates(source["obj"], max_vms=10)
            for vm_item in vm_candidates:
                vm_id_key = str(vm_item.get("vm_id") or vm_item.get("vm_name"))
                if vm_id_key in seen_vm_ids:
                    continue

                move_size_bytes = float(vm_item["size_bytes"])
                for target in targets:
                    if target["id"] == source["id"]:
                        continue

                    source_after = _simulate_used_pct_after_move(source, move_size_bytes, is_source=True)
                    target_after = _simulate_used_pct_after_move(target, move_size_bytes, is_source=False)
                    if source_after is None or target_after is None:
                        continue

                    fit = _evaluate_target_fit(
                        capacity_bytes=float(target.get("capacity_bytes", 0) or 0),
                        free_bytes=float(target.get("free_bytes", 0) or 0),
                        vm_size_bytes=move_size_bytes,
                        policy=policy,
                    )
                    if not fit["compatible"]:
                        continue

                    source_used = float(source.get("used_pct") or 0.0)
                    target_used = float(target.get("used_pct") or 0.0)
                    source_relief = max(0.0, source_used - source_after)
                    before_gap = abs(source_used - target_used)
                    after_gap = abs(source_after - target_after)
                    balance_gain = max(0.0, before_gap - after_gap)
                    pressure_bonus = max(0.0, source_used - avg_used)
                    size_bonus = min(12.0, float(vm_item["size_gb"]) / 25.0)
                    target_safety_bonus = max(0.0, min(15.0, (85.0 - target_after) * 0.6))
                    penalty = max(0.0, (target_after - 85.0) * 0.8)

                    score_raw = (
                        (balance_gain * 3.8)
                        + (source_relief * 2.0)
                        + (pressure_bonus * 1.1)
                        + size_bonus
                        + target_safety_bonus
                        - penalty
                    )
                    score = max(0, min(100, int(round(score_raw))))

                    items.append(
                        {
                            "key": f"cand-{cluster_id}-{vm_id_key}-{source['id']}-{target['id']}",
                            "cluster_id": getattr(pod, "_moId", None),
                            "cluster_name": getattr(pod, "name", "unknown"),
                            "vm_id": vm_item.get("vm_id"),
                            "vm_name": vm_item.get("vm_name"),
                            "size_gb": round(float(vm_item["size_gb"]), 2),
                            "source_ds_id": source["id"],
                            "source_ds": source["name"],
                            "target_ds_id": target["id"],
                            "target_ds": target["name"],
                            "source_used_pct": round(source_used, 2),
                            "target_used_pct": round(target_used, 2),
                            "source_used_after_pct": source_after,
                            "target_used_after_pct": target_after,
                            "balance_gap_before_pct": round(before_gap, 2),
                            "balance_gap_after_pct": round(after_gap, 2),
                            "balance_gain_pct": round(balance_gain, 2),
                            "score": score,
                            "score_breakdown": {
                                "balance_gain": round(balance_gain, 2),
                                "source_relief": round(source_relief, 2),
                                "pressure_bonus": round(pressure_bonus, 2),
                                "size_bonus": round(size_bonus, 2),
                                "target_safety_bonus": round(target_safety_bonus, 2),
                                "penalty": round(penalty, 2),
                            },
                            "reason": (
                                f"Gap {before_gap:.1f}%→{after_gap:.1f}% | fonte {source_used:.1f}%→{source_after:.1f}% | "
                                f"destino {target_used:.1f}%→{target_after:.1f}%."
                            ),
                            "origin": "heuristic_read_only",
                        }
                    )

                    seen_vm_ids.add(vm_id_key)
                    break

                if len(items) >= limit:
                    break

            if len(items) >= limit:
                break

        items.sort(
            key=lambda item: (
                int(item.get("score", 0)),
                float(item.get("balance_gain_pct", 0.0)),
            ),
            reverse=True,
        )
        return {
            "cluster_id": getattr(pod, "_moId", None),
            "cluster_name": getattr(pod, "name", "unknown"),
            "avg_used_pct": avg_used,
            "source_threshold_pct": round(source_threshold, 2),
            "target_threshold_pct": round(target_threshold, 2),
            "policy": policy,
            "items": items[:limit],
            "reason": "ok" if items else "no_viable_candidates",
        }


def _space_metrics_from_state(ds_state: dict[str, dict[str, Any]]) -> dict[str, Any]:
    used_values: list[float] = []
    total_capacity_bytes = 0.0
    total_free_bytes = 0.0

    for item in ds_state.values():
        capacity = float(item.get("capacity_bytes", 0.0) or 0.0)
        free = float(item.get("free_bytes", 0.0) or 0.0)
        if capacity <= 0:
            continue
        total_capacity_bytes += capacity
        total_free_bytes += free
        used_pct = _calc_used_pct_from_capacity_free(capacity, free)
        if used_pct is not None:
            used_values.append(float(used_pct))

    avg_used = round(sum(used_values) / len(used_values), 2) if used_values else 0.0
    max_used = round(max(used_values), 2) if used_values else 0.0
    min_used = round(min(used_values), 2) if used_values else 0.0
    imbalance = round(max_used - min_used, 2) if used_values else 0.0

    return {
        "datastore_count": len(ds_state),
        "total_capacity_gb": _to_gb(total_capacity_bytes),
        "total_free_gb": _to_gb(total_free_bytes),
        "avg_used_pct": avg_used,
        "max_used_pct": max_used,
        "min_used_pct": min_used,
        "space_imbalance_pct": imbalance,
    }


def _build_simulated_plan_sync(
    client: VCenterClient,
    cluster_id: str,
    max_moves: int = 3,
) -> dict[str, Any]:
    safe_max_moves = max(1, min(10, int(max_moves)))
    candidate_payload = _build_move_candidates_sync(client, cluster_id, limit=max(safe_max_moves * 25, 50))
    policy = _get_move_policy()

    with _service_instance(client) as si:
        content = si.RetrieveContent()
        pod = _find_storage_pod(content, cluster_id)
        if pod is None:
            return {
                "cluster_id": cluster_id,
                "cluster_name": None,
                "max_moves": safe_max_moves,
                "policy": policy,
                "before": {},
                "after": {},
                "delta": {},
                "items": [],
                "reason": "cluster_not_found",
            }

        datastores = _get_member_datastores(pod)
        ds_state: dict[str, dict[str, Any]] = {}
        for ds in datastores:
            ds_id = getattr(ds, "_moId", None)
            if not ds_id:
                continue
            snap = _datastore_space_snapshot(ds)
            ds_state[str(ds_id)] = {
                "name": snap["datastore_name"],
                "capacity_bytes": float(snap["_capacity_bytes"]),
                "free_bytes": float(snap["_free_bytes"]),
            }

    before_state = {
        ds_id: {
            "name": item["name"],
            "capacity_bytes": float(item["capacity_bytes"]),
            "free_bytes": float(item["free_bytes"]),
        }
        for ds_id, item in ds_state.items()
    }
    before_metrics = _space_metrics_from_state(before_state)

    candidate_items = list(candidate_payload.get("items", []) or [])
    selected: list[dict[str, Any]] = []
    moved_vms: set[str] = set()

    for cand in candidate_items:
        if len(selected) >= safe_max_moves:
            break

        vm_id = str(cand.get("vm_id") or cand.get("vm_name") or "")
        source_id = str(cand.get("source_ds_id") or "")
        target_id = str(cand.get("target_ds_id") or "")
        size_gb = float(cand.get("size_gb") or 0.0)
        move_size_bytes = size_gb * GB

        if not vm_id or vm_id in moved_vms:
            continue
        if not source_id or not target_id or source_id == target_id:
            continue
        if move_size_bytes <= 0:
            continue
        if source_id not in ds_state or target_id not in ds_state:
            continue

        source_state = ds_state[source_id]
        target_state = ds_state[target_id]

        source_capacity = float(source_state["capacity_bytes"])
        source_free = float(source_state["free_bytes"])
        target_capacity = float(target_state["capacity_bytes"])
        target_free = float(target_state["free_bytes"])

        if source_capacity <= 0 or target_capacity <= 0:
            continue

        fit = _evaluate_target_fit(
            capacity_bytes=target_capacity,
            free_bytes=target_free,
            vm_size_bytes=move_size_bytes,
            policy=policy,
        )
        if not fit["compatible"]:
            continue

        source_projected_free = max(0.0, min(source_capacity, source_free + move_size_bytes))
        target_projected_free = float(fit["projected_free_bytes"])

        source_state["free_bytes"] = source_projected_free
        target_state["free_bytes"] = target_projected_free

        selected.append(
            {
                "key": cand.get("key"),
                "vm_id": cand.get("vm_id"),
                "vm_name": cand.get("vm_name"),
                "size_gb": round(size_gb, 2),
                "source_ds_id": source_id,
                "source_ds": source_state["name"],
                "target_ds_id": target_id,
                "target_ds": target_state["name"],
                "source_used_after_pct": _calc_used_pct_from_capacity_free(source_capacity, source_projected_free),
                "target_used_after_pct": _calc_used_pct_from_capacity_free(target_capacity, target_projected_free),
                "score": int(cand.get("score", 0) or 0),
                "reason": cand.get("reason"),
            }
        )
        moved_vms.add(vm_id)

    after_metrics = _space_metrics_from_state(ds_state)
    delta = {
        "avg_used_pct_delta": round(float(after_metrics.get("avg_used_pct", 0.0)) - float(before_metrics.get("avg_used_pct", 0.0)), 2),
        "space_imbalance_pct_delta": round(
            float(after_metrics.get("space_imbalance_pct", 0.0)) - float(before_metrics.get("space_imbalance_pct", 0.0)),
            2,
        ),
        "total_free_gb_delta": round(
            float(after_metrics.get("total_free_gb", 0.0) or 0.0) - float(before_metrics.get("total_free_gb", 0.0) or 0.0),
            2,
        ),
    }

    return {
        "cluster_id": candidate_payload.get("cluster_id", cluster_id),
        "cluster_name": candidate_payload.get("cluster_name"),
        "max_moves": safe_max_moves,
        "policy": policy,
        "before": before_metrics,
        "after": after_metrics,
        "delta": delta,
        "items": selected,
        "reason": "ok" if selected else str(candidate_payload.get("reason") or "no_viable_candidates"),
        "source_candidates": len(candidate_items),
    }


def _find_datastore_in_pod(pod: Any, datastore_id: str) -> Any | None:
    for ds in _get_member_datastores(pod):
        if getattr(ds, "_moId", None) == datastore_id:
            return ds
    return None


def _calc_used_pct_from_capacity_free(capacity_bytes: float, free_bytes: float) -> float | None:
    try:
        if capacity_bytes <= 0:
            return None
        used = capacity_bytes - free_bytes
        return round((used / capacity_bytes) * 100.0, 2)
    except Exception:
        return None


def _calc_free_pct_from_capacity_free(capacity_bytes: float, free_bytes: float) -> float | None:
    try:
        if capacity_bytes <= 0:
            return None
        return round((free_bytes / capacity_bytes) * 100.0, 2)
    except Exception:
        return None


def _evaluate_target_fit(capacity_bytes: float, free_bytes: float, vm_size_bytes: float, policy: dict[str, float | int]) -> dict[str, Any]:
    headroom_pct = float(policy.get("min_free_headroom_pct", 15.0))
    reserve_ratio = float(policy.get("min_vm_reserve_ratio", 0.10))
    max_target_used_pct = float(policy.get("max_target_used_pct", 95.0))

    projected_free_bytes = max(0.0, min(capacity_bytes, free_bytes - vm_size_bytes))
    projected_used_pct = _calc_used_pct_from_capacity_free(capacity_bytes, projected_free_bytes)
    projected_free_pct = _calc_free_pct_from_capacity_free(capacity_bytes, projected_free_bytes)

    reserve_bytes = max(capacity_bytes * (headroom_pct / 100.0), vm_size_bytes * reserve_ratio)

    reasons: list[str] = []
    if free_bytes <= (vm_size_bytes + reserve_bytes):
        reasons.append("insufficient_free_space_with_reserve")
    if projected_used_pct is not None and projected_used_pct >= max_target_used_pct:
        reasons.append("projected_usage_too_high")
    if projected_free_pct is not None and projected_free_pct < headroom_pct:
        reasons.append("projected_headroom_too_low")

    return {
        "compatible": not reasons,
        "reasons": reasons,
        "projected_free_bytes": projected_free_bytes,
        "projected_free_pct": projected_free_pct,
        "projected_used_pct": projected_used_pct,
        "reserve_bytes": reserve_bytes,
    }


def _datastore_space_snapshot(datastore: Any) -> dict[str, Any]:
    summary = _safe_get(datastore, "summary")
    capacity = float(_safe_get(summary, "capacity", default=0) or 0)
    free = float(_safe_get(summary, "freeSpace", default=0) or 0)
    return {
        "datastore_id": getattr(datastore, "_moId", None),
        "datastore_name": getattr(datastore, "name", "unknown"),
        "capacity_gb": _to_gb(capacity),
        "free_gb": _to_gb(free),
        "used_pct": _calc_used_pct_from_capacity_free(capacity, free),
        "_capacity_bytes": capacity,
        "_free_bytes": free,
    }


def _find_vm_in_datastores(datastores: list[Any], vm_id: str) -> tuple[Any | None, Any | None]:
    for ds in datastores:
        for vm in list(getattr(ds, "vm", []) or []):
            if getattr(vm, "_moId", None) == vm_id:
                return vm, ds
    return None, None


def _vm_power_state(vm: Any) -> str:
    runtime = _safe_get(vm, "runtime")
    state = _safe_get(runtime, "powerState")
    if state is None:
        return "unknown"
    return str(state)


def _vm_home_datastore_name(vm: Any) -> str | None:
    """
    Best effort para extrair datastore home da VM a partir de vmPathName:
    [datastore-name] vm/vm.vmx
    """
    try:
        path = str(_safe_get(_safe_get(_safe_get(vm, "config"), "files"), "vmPathName") or "")
        if not path.startswith("["):
            return None
        right = path.find("]")
        if right <= 1:
            return None
        return path[1:right]
    except Exception:
        return None


def _list_datastore_vms_sync(client: VCenterClient, cluster_id: str, datastore_id: str) -> dict[str, Any]:
    with _service_instance(client) as si:
        content = si.RetrieveContent()
        pod = _find_storage_pod(content, cluster_id)
        if pod is None:
            return {
                "cluster_id": cluster_id,
                "cluster_name": None,
                "datastore_id": datastore_id,
                "datastore_name": None,
                "items": [],
                "reason": "cluster_not_found",
            }

        datastore = _find_datastore_in_pod(pod, datastore_id)
        if datastore is None:
            return {
                "cluster_id": cluster_id,
                "cluster_name": getattr(pod, "name", "unknown"),
                "datastore_id": datastore_id,
                "datastore_name": None,
                "items": [],
                "reason": "datastore_not_found",
            }

        items: list[dict[str, Any]] = []
        for vm in list(getattr(datastore, "vm", []) or []):
            try:
                size_gb = _estimate_vm_size_gb(vm)
                items.append(
                    {
                        "vm_id": getattr(vm, "_moId", None),
                        "vm_name": getattr(vm, "name", "unknown"),
                        "power_state": _vm_power_state(vm),
                        "size_gb": size_gb,
                        "home_datastore": _vm_home_datastore_name(vm),
                    }
                )
            except Exception:
                logger.exception(
                    "Falha ao montar item de VM no datastore %s",
                    getattr(datastore, "name", "unknown"),
                )

        items.sort(
            key=lambda item: (
                -(float(item["size_gb"]) if item.get("size_gb") is not None else 0.0),
                str(item.get("vm_name") or ""),
            )
        )

        return {
            "cluster_id": getattr(pod, "_moId", None),
            "cluster_name": getattr(pod, "name", "unknown"),
            "datastore_id": getattr(datastore, "_moId", None),
            "datastore_name": getattr(datastore, "name", "unknown"),
            "items": items,
            "reason": "ok",
        }


def _is_relocate_task(info: Any) -> bool:
    description_id = str(_safe_get(info, "descriptionId", default="") or "").lower()
    name = str(_safe_get(info, "name", default="") or "").lower()
    operation_name = str(_safe_get(_safe_get(info, "description"), "label", default="") or "").lower()
    text = " ".join([description_id, name, operation_name])
    return "relocate" in text or "storage vmotion" in text


def _count_active_relocate_tasks_for_cluster(content: Any, pod: Any) -> int:
    datastore_ids = {
        str(getattr(ds, "_moId", ""))
        for ds in _get_member_datastores(pod)
        if getattr(ds, "_moId", None)
    }
    if not datastore_ids:
        return 0

    view = None
    count = 0
    try:
        view = content.viewManager.CreateContainerView(content.rootFolder, [vim.Task], True)
        for task in list(view.view or []):
            info = _safe_get(task, "info")
            state = str(_safe_get(info, "state", default="") or "").lower()
            if state not in {"queued", "running"}:
                continue
            if not _is_relocate_task(info):
                continue

            entity = _safe_get(info, "entity")
            if not isinstance(entity, vim.VirtualMachine):
                continue

            vm_datastores = list(getattr(entity, "datastore", []) or [])
            for vm_ds in vm_datastores:
                vm_ds_id = str(getattr(vm_ds, "_moId", "") or "")
                if vm_ds_id in datastore_ids:
                    count += 1
                    break
    except Exception:
        logger.warning("Não foi possível contar tasks de migração ativas no cluster.", exc_info=True)
        return 0
    finally:
        if view:
            try:
                view.Destroy()
            except Exception:
                logger.debug("Falha ao destruir ContainerView de Task na contagem de migração", exc_info=True)
    return count


def _move_vm_sync(
    client: VCenterClient,
    cluster_id: str,
    vm_id: str,
    target_datastore_id: str,
    source_datastore_id: str | None = None,
) -> dict[str, Any]:
    with _service_instance(client) as si:
        policy = _get_move_policy()
        content = si.RetrieveContent()
        pod = _find_storage_pod(content, cluster_id)
        if pod is None:
            raise SDRSOperationError("Datastore cluster não encontrado.")

        datastores = _get_member_datastores(pod)
        target_ds = next((ds for ds in datastores if getattr(ds, "_moId", None) == target_datastore_id), None)
        if target_ds is None:
            raise SDRSOperationError("Datastore de destino não encontrado no cluster.")

        source_ds = None
        if source_datastore_id:
            source_ds = next((ds for ds in datastores if getattr(ds, "_moId", None) == source_datastore_id), None)
            if source_ds is None:
                raise SDRSOperationError("Datastore de origem não encontrado no cluster.")

        vm_obj = None
        vm_source_ds = None

        scan_datastores = [source_ds] if source_ds is not None else datastores
        for ds in scan_datastores:
            for vm in list(getattr(ds, "vm", []) or []):
                if getattr(vm, "_moId", None) == vm_id:
                    vm_obj = vm
                    vm_source_ds = ds
                    break
            if vm_obj is not None:
                break

        if vm_obj is None:
            raise SDRSOperationError("VM não encontrada no cluster/datastore informado.")

        if vm_source_ds is not None and getattr(vm_source_ds, "_moId", None) == target_datastore_id:
            raise SDRSOperationError("Datastore de destino é igual ao datastore atual da VM.")

        active_migrations = _count_active_relocate_tasks_for_cluster(content, pod)
        max_concurrent = int(policy.get("max_concurrent_per_cluster", 2))
        if active_migrations >= max_concurrent:
            raise SDRSOperationError(
                f"Limite de migrações simultâneas atingido no cluster ({active_migrations}/{max_concurrent})."
            )

        vm_size_gb = _estimate_vm_size_gb(vm_obj)
        if vm_size_gb is None or vm_size_gb <= 0:
            raise SDRSOperationError("Não foi possível estimar o tamanho da VM para validar segurança de destino.")
        vm_size_bytes = float(vm_size_gb) * GB

        target_snap = _datastore_space_snapshot(target_ds)
        fit = _evaluate_target_fit(
            capacity_bytes=float(target_snap["_capacity_bytes"]),
            free_bytes=float(target_snap["_free_bytes"]),
            vm_size_bytes=vm_size_bytes,
            policy=policy,
        )
        if not fit["compatible"]:
            reasons = ", ".join(fit["reasons"]) if fit["reasons"] else "restrições de capacidade"
            raise SDRSOperationError(f"Datastore de destino não passou nas regras de segurança: {reasons}.")

        relocate_spec = vim.vm.RelocateSpec()
        relocate_spec.datastore = target_ds

        try:
            _enforce_storage_relocate_only(vm_obj)
            task = vm_obj.RelocateVM_Task(spec=relocate_spec, priority=vim.VirtualMachine.MovePriority.defaultPriority)
        except Exception as exc:
            raise SDRSOperationError(f"Falha ao iniciar migração da VM: {exc}") from exc

        return {
            "queued": True,
            "cluster_id": getattr(pod, "_moId", None),
            "cluster_name": getattr(pod, "name", "unknown"),
            "vm_id": getattr(vm_obj, "_moId", None),
            "vm_name": getattr(vm_obj, "name", "unknown"),
            "source_datastore_id": getattr(vm_source_ds, "_moId", None) if vm_source_ds else source_datastore_id,
            "source_datastore_name": getattr(vm_source_ds, "name", None) if vm_source_ds else None,
            "target_datastore_id": getattr(target_ds, "_moId", None),
            "target_datastore_name": getattr(target_ds, "name", "unknown"),
            "policy": policy,
            "projected_target_used_pct": fit["projected_used_pct"],
            "projected_target_free_pct": fit["projected_free_pct"],
            "task_id": getattr(task, "_moId", None),
            "message": "Storage vMotion enfileirada com sucesso.",
        }


def _build_move_options_sync(
    client: VCenterClient,
    cluster_id: str,
    vm_id: str,
    source_datastore_id: str | None = None,
) -> dict[str, Any]:
    with _service_instance(client) as si:
        content = si.RetrieveContent()
        pod = _find_storage_pod(content, cluster_id)
        if pod is None:
            return {
                "cluster_id": cluster_id,
                "cluster_name": None,
                "vm_id": vm_id,
                "vm_name": None,
                "source_datastore_id": source_datastore_id,
                "source_datastore_name": None,
                "vm_size_gb": None,
                "targets": [],
                "reason": "cluster_not_found",
            }

        datastores = _get_member_datastores(pod)
        policy = _get_move_policy()

        vm_obj = None
        source_ds = None
        if source_datastore_id:
            source_ds = next((ds for ds in datastores if getattr(ds, "_moId", None) == source_datastore_id), None)
            if source_ds is None:
                return {
                    "cluster_id": getattr(pod, "_moId", None),
                    "cluster_name": getattr(pod, "name", "unknown"),
                    "vm_id": vm_id,
                    "vm_name": None,
                    "source_datastore_id": source_datastore_id,
                    "source_datastore_name": None,
                    "vm_size_gb": None,
                    "targets": [],
                    "reason": "source_datastore_not_found",
                }
            vm_obj, source_found = _find_vm_in_datastores([source_ds], vm_id)
            source_ds = source_found
        else:
            vm_obj, source_ds = _find_vm_in_datastores(datastores, vm_id)

        if vm_obj is None or source_ds is None:
            return {
                "cluster_id": getattr(pod, "_moId", None),
                "cluster_name": getattr(pod, "name", "unknown"),
                "vm_id": vm_id,
                "vm_name": None,
                "source_datastore_id": source_datastore_id,
                "source_datastore_name": None,
                "vm_size_gb": None,
                "targets": [],
                "reason": "vm_not_found",
            }

        vm_size_gb = _estimate_vm_size_gb(vm_obj)
        if vm_size_gb is None or vm_size_gb <= 0:
            return {
                "cluster_id": getattr(pod, "_moId", None),
                "cluster_name": getattr(pod, "name", "unknown"),
                "vm_id": getattr(vm_obj, "_moId", None),
                "vm_name": getattr(vm_obj, "name", "unknown"),
                "source_datastore_id": getattr(source_ds, "_moId", None),
                "source_datastore_name": getattr(source_ds, "name", "unknown"),
                "vm_size_gb": None,
                "targets": [],
                "reason": "vm_size_unavailable",
            }

        vm_size_bytes = float(vm_size_gb) * GB
        source_snap = _datastore_space_snapshot(source_ds)
        source_proj_free_bytes = float(source_snap["_free_bytes"]) + vm_size_bytes
        source_proj_free_bytes = max(0.0, min(float(source_snap["_capacity_bytes"]), source_proj_free_bytes))
        source_projected = {
            "free_gb": _to_gb(source_proj_free_bytes),
            "used_pct": _calc_used_pct_from_capacity_free(float(source_snap["_capacity_bytes"]), source_proj_free_bytes),
        }

        targets: list[dict[str, Any]] = []
        for ds in datastores:
            if getattr(ds, "_moId", None) == getattr(source_ds, "_moId", None):
                continue

            snap = _datastore_space_snapshot(ds)
            capacity_bytes = float(snap["_capacity_bytes"])
            free_bytes = float(snap["_free_bytes"])
            fit = _evaluate_target_fit(
                capacity_bytes=capacity_bytes,
                free_bytes=free_bytes,
                vm_size_bytes=vm_size_bytes,
                policy=policy,
            )

            targets.append(
                {
                    "datastore_id": snap["datastore_id"],
                    "datastore_name": snap["datastore_name"],
                    "current_free_gb": snap["free_gb"],
                    "current_used_pct": snap["used_pct"],
                    "projected_free_gb": _to_gb(fit["projected_free_bytes"]),
                    "projected_free_pct": fit["projected_free_pct"],
                    "projected_used_pct": fit["projected_used_pct"],
                    "compatible": fit["compatible"],
                    "reasons": fit["reasons"],
                }
            )

        targets.sort(
            key=lambda item: (
                0 if item["compatible"] else 1,
                float(item["projected_used_pct"]) if item.get("projected_used_pct") is not None else 999.0,
                str(item.get("datastore_name") or ""),
            )
        )

        return {
            "cluster_id": getattr(pod, "_moId", None),
            "cluster_name": getattr(pod, "name", "unknown"),
            "vm_id": getattr(vm_obj, "_moId", None),
            "vm_name": getattr(vm_obj, "name", "unknown"),
            "vm_power_state": _vm_power_state(vm_obj),
            "vm_size_gb": round(float(vm_size_gb), 2),
            "source_datastore_id": getattr(source_ds, "_moId", None),
            "source_datastore_name": getattr(source_ds, "name", "unknown"),
            "source_current_free_gb": source_snap["free_gb"],
            "source_current_used_pct": source_snap["used_pct"],
            "source_projected_free_gb": source_projected["free_gb"],
            "source_projected_used_pct": source_projected["used_pct"],
            "policy": policy,
            "targets": targets,
            "reason": "ok",
        }


def _find_task_by_moid(content: Any, task_id: str) -> Any | None:
    view = None
    try:
        view = content.viewManager.CreateContainerView(
            content.rootFolder,
            [vim.Task],
            True,
        )
        for task in list(view.view or []):
            if getattr(task, "_moId", None) == task_id:
                return task
        return None
    finally:
        if view:
            try:
                view.Destroy()
            except Exception:
                logger.debug("Falha ao destruir ContainerView de Task", exc_info=True)


def _to_iso_or_none(value: Any) -> str | None:
    if value is None:
        return None
    try:
        return value.isoformat()
    except Exception:
        return str(value)


def _get_task_status_sync(client: VCenterClient, task_id: str) -> dict[str, Any]:
    with _service_instance(client) as si:
        content = si.RetrieveContent()
        task = _find_task_by_moid(content, task_id)
        if task is None:
            return {
                "task_id": task_id,
                "found": False,
                "reason": "task_not_found",
            }

        info = _safe_get(task, "info")
        state = str(_safe_get(info, "state", default="unknown") or "unknown")
        progress_raw = _safe_get(info, "progress")
        progress = None
        try:
            if progress_raw is not None:
                progress = int(progress_raw)
        except Exception:
            progress = None

        error_obj = _safe_get(info, "error")
        error_message = None
        if error_obj is not None:
            error_message = str(_safe_get(error_obj, "localizedMessage", "msg", default="") or "") or str(error_obj)

        result = _safe_get(info, "result")
        result_repr: Any
        if result is None:
            result_repr = None
        elif hasattr(result, "_moId"):
            result_repr = getattr(result, "_moId", None)
        else:
            result_repr = str(result)

        return {
            "task_id": task_id,
            "found": True,
            "state": state,
            "progress": progress,
            "error": error_message,
            "description": str(_safe_get(_safe_get(info, "description"), "message", default="") or ""),
            "entity_name": str(_safe_get(info, "entityName", default="") or ""),
            "queue_time": _to_iso_or_none(_safe_get(info, "queueTime")),
            "start_time": _to_iso_or_none(_safe_get(info, "startTime")),
            "complete_time": _to_iso_or_none(_safe_get(info, "completeTime")),
            "result": result_repr,
            "reason": "ok",
        }


async def list_clusters(client: VCenterClient) -> list[dict[str, Any]]:
    try:
        return await asyncio.to_thread(_list_clusters_sync, client)
    except Exception:
        logger.exception("Erro ao listar datastore clusters SDRS")
        return []


async def get_cluster_detail(client: VCenterClient, cluster_id: str) -> dict[str, Any]:
    try:
        return await asyncio.to_thread(_get_cluster_detail_sync, client, cluster_id)
    except Exception:
        logger.exception("Erro ao obter detalhe do datastore cluster %s", cluster_id)
        return {}


async def get_pending_recommendations(client: VCenterClient, cluster_id: str) -> list[dict[str, Any]]:
    try:
        return await asyncio.to_thread(_get_pending_recommendations_sync, client, cluster_id)
    except Exception:
        logger.exception("Erro ao obter recomendações SDRS do cluster %s", cluster_id)
        return []


async def get_move_candidates(client: VCenterClient, cluster_id: str, limit: int = 20) -> dict[str, Any]:
    try:
        safe_limit = max(1, min(int(limit), 50))
        return await asyncio.to_thread(_build_move_candidates_sync, client, cluster_id, safe_limit)
    except Exception:
        logger.exception("Erro ao obter candidatos de migração do cluster %s", cluster_id)
        return {
            "cluster_id": cluster_id,
            "cluster_name": None,
            "policy": _get_move_policy(),
            "items": [],
            "reason": "unexpected_error",
        }


async def get_simulated_move_plan(client: VCenterClient, cluster_id: str, max_moves: int = 3) -> dict[str, Any]:
    safe_max_moves = max(1, min(int(max_moves), 10))
    try:
        return await asyncio.to_thread(_build_simulated_plan_sync, client, cluster_id, safe_max_moves)
    except Exception:
        logger.exception("Erro ao gerar simulação de plano de migração do cluster %s", cluster_id)
        return {
            "cluster_id": cluster_id,
            "cluster_name": None,
            "max_moves": safe_max_moves,
            "policy": _get_move_policy(),
            "before": {},
            "after": {},
            "delta": {},
            "items": [],
            "reason": "unexpected_error",
        }


async def diagnose_latency_collection(
    client: VCenterClient,
    cluster_id: str | None = None,
    max_datastores_per_cluster: int = 3,
) -> dict[str, Any]:
    try:
        return await asyncio.to_thread(
            _diagnose_latency_collection_sync,
            client,
            cluster_id,
            max_datastores_per_cluster,
        )
    except Exception:
        logger.exception("Erro ao diagnosticar coleta de latência SDRS")
        return {
            "host": client.host,
            "cluster_filter": cluster_id,
            "error": "Erro inesperado ao diagnosticar latência.",
            "clusters": [],
        }


async def list_datastore_vms(client: VCenterClient, cluster_id: str, datastore_id: str) -> dict[str, Any]:
    try:
        return await asyncio.to_thread(_list_datastore_vms_sync, client, cluster_id, datastore_id)
    except Exception:
        logger.exception(
            "Erro ao listar VMs do datastore datastore_id=%s cluster_id=%s",
            datastore_id,
            cluster_id,
        )
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
        return await asyncio.to_thread(
            _move_vm_sync,
            client,
            cluster_id,
            vm_id,
            target_datastore_id,
            source_datastore_id,
        )
    except SDRSOperationError:
        raise
    except Exception as exc:
        logger.exception(
            "Erro ao mover VM vm_id=%s cluster_id=%s target_ds=%s",
            vm_id,
            cluster_id,
            target_datastore_id,
        )
        raise SDRSOperationError(f"Erro inesperado ao solicitar migração da VM: {exc}") from exc


async def get_move_options_for_vm(
    client: VCenterClient,
    cluster_id: str,
    vm_id: str,
    source_datastore_id: str | None = None,
) -> dict[str, Any]:
    try:
        return await asyncio.to_thread(
            _build_move_options_sync,
            client,
            cluster_id,
            vm_id,
            source_datastore_id,
        )
    except Exception:
        logger.exception(
            "Erro ao obter opções de destino para VM vm_id=%s cluster_id=%s",
            vm_id,
            cluster_id,
        )
        return {
            "cluster_id": cluster_id,
            "cluster_name": None,
            "vm_id": vm_id,
            "vm_name": None,
            "source_datastore_id": source_datastore_id,
            "source_datastore_name": None,
            "vm_size_gb": None,
            "policy": _get_move_policy(),
            "targets": [],
            "reason": "unexpected_error",
        }


async def get_task_status(client: VCenterClient, task_id: str) -> dict[str, Any]:
    try:
        return await asyncio.to_thread(_get_task_status_sync, client, task_id)
    except Exception:
        logger.exception("Erro ao obter status da task %s", task_id)
        return {
            "task_id": task_id,
            "found": False,
            "reason": "unexpected_error",
        }
