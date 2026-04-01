
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
MANUAL_CLUSTER_ID = "manual-storage-cluster"
MANUAL_CLUSTER_NAME = "Manual Storage vMotion"


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
        if si is not None:
            try:
                Disconnect(si)
            except Exception:
                logger.debug("Falha ao desconectar sessão pyVmomi host=%s", client.host, exc_info=True)


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


def _inventory_sync(client: VCenterClient) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    with _service_instance(client) as si:
        content = si.RetrieveContent()
        with _view(content, [vim.Datastore]) as ds_view:
            datastores = [_serialize_datastore(ds_obj) for ds_obj in ds_view]
        with _view(content, [vim.VirtualMachine]) as vm_view:
            vms = [_serialize_vm(vm_obj) for vm_obj in vm_view]

    datastores.sort(key=lambda x: str(x.get("name") or "").lower())
    vms.sort(key=lambda x: str(x.get("vm_name") or "").lower())
    return datastores, vms

def _cluster_summary(datastores: list[dict[str, Any]]) -> dict[str, Any]:
    total_free = round(sum(_to_float(ds.get("free_gb"), 0.0) for ds in datastores), 2)
    total_capacity = round(sum(_to_float(ds.get("capacity_gb"), 0.0) for ds in datastores), 2)
    return {
        "id": MANUAL_CLUSTER_ID,
        "name": MANUAL_CLUSTER_NAME,
        "sdrs_enabled": False,
        "sdrs_automation_level": "Manual",
        "free_space_threshold": None,
        "io_latency_threshold": None,
        "datastore_count": len(datastores),
        "total_free_gb": total_free,
        "total_capacity_gb": total_capacity,
    }


def _cluster_detail(datastores: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "id": MANUAL_CLUSTER_ID,
        "name": MANUAL_CLUSTER_NAME,
        "sdrs_enabled": False,
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
    datastores, _ = _inventory_sync(client)
    if not datastores:
        return []
    return [_cluster_summary(datastores)]


def _get_cluster_detail_sync(client: VCenterClient, cluster_id: str) -> dict[str, Any]:
    datastores, _ = _inventory_sync(client)
    if not datastores:
        return {}
    if cluster_id != MANUAL_CLUSTER_ID:
        return {}
    return _cluster_detail(datastores)


def _get_pending_recommendations_sync(client: VCenterClient, cluster_id: str) -> list[dict[str, Any]]:
    _ = client
    _ = cluster_id
    return []


def _build_move_candidates_sync(client: VCenterClient, cluster_id: str, limit: int = 20) -> dict[str, Any]:
    _ = client
    _ = limit
    return {
        "cluster_id": cluster_id,
        "cluster_name": MANUAL_CLUSTER_NAME,
        "policy": _move_policy(),
        "items": [],
        "reason": "ok",
    }


def _build_simulated_plan_sync(client: VCenterClient, cluster_id: str, max_moves: int = 3) -> dict[str, Any]:
    datastores, _ = _inventory_sync(client)
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
        "cluster_name": MANUAL_CLUSTER_NAME,
        "max_moves": max_moves,
        "policy": _move_policy(),
        "before": {"avg_used_pct": avg_used, "space_imbalance_pct": imbalance},
        "after": {"avg_used_pct": avg_used, "space_imbalance_pct": imbalance},
        "delta": {"avg_used_pct_delta": 0.0, "space_imbalance_pct_delta": 0.0},
        "source_candidates": 0,
        "items": [],
        "reason": "ok",
    }


def _diagnose_latency_collection_sync(client: VCenterClient, cluster_id: str | None = None, max_datastores_per_cluster: int = 3) -> dict[str, Any]:
    _ = max_datastores_per_cluster
    return {
        "host": client.host,
        "cluster_filter": cluster_id,
        "message": "Latency diagnostics disabled in manual migration mode.",
        "clusters": [],
    }

def _list_datastore_vms_sync(client: VCenterClient, cluster_id: str, datastore_id: str) -> dict[str, Any]:
    datastores, vms = _inventory_sync(client)

    if cluster_id != MANUAL_CLUSTER_ID:
        return {
            "cluster_id": cluster_id,
            "cluster_name": None,
            "datastore_id": datastore_id,
            "datastore_name": None,
            "items": [],
            "reason": "cluster_not_found",
        }

    ds = _find_datastore(datastores, datastore_id)
    if ds is None:
        return {
            "cluster_id": cluster_id,
            "cluster_name": MANUAL_CLUSTER_NAME,
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
        "cluster_name": MANUAL_CLUSTER_NAME,
        "datastore_id": datastore_id,
        "datastore_name": ds.get("name"),
        "items": items,
        "reason": "ok",
    }


def _move_options_for_vm_sync(client: VCenterClient, cluster_id: str, vm_id: str, source_datastore_id: str | None = None) -> dict[str, Any]:
    datastores, vms = _inventory_sync(client)
    policy = _move_policy()

    if cluster_id != MANUAL_CLUSTER_ID:
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

    vm = _find_vm(vms, vm_id)
    if vm is None:
        return {
            "cluster_id": cluster_id,
            "cluster_name": MANUAL_CLUSTER_NAME,
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
            "cluster_name": MANUAL_CLUSTER_NAME,
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
            "cluster_name": MANUAL_CLUSTER_NAME,
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
        "cluster_name": MANUAL_CLUSTER_NAME,
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
    if cluster_id != MANUAL_CLUSTER_ID:
        raise SDRSOperationError("Datastore cluster não encontrado.")

    with _service_instance(client) as si:
        content = si.RetrieveContent()

        with _view(content, [vim.VirtualMachine]) as vm_view:
            vm_obj = next((obj for obj in vm_view if getattr(obj, "_moId", None) == vm_id), None)
        if vm_obj is None:
            raise SDRSOperationError("VM não encontrada.")

        with _view(content, [vim.Datastore]) as ds_view:
            target_ds = next((obj for obj in ds_view if getattr(obj, "_moId", None) == target_datastore_id), None)
            source_ds = None
            if source_datastore_id:
                source_ds = next((obj for obj in ds_view if getattr(obj, "_moId", None) == source_datastore_id), None)

        current_ds = _primary_vm_datastore(vm_obj)
        if source_ds is None:
            source_ds = current_ds

        if source_ds is None:
            raise SDRSOperationError("Datastore de origem da VM não identificado.")
        if target_ds is None:
            raise SDRSOperationError("Datastore de destino não encontrado.")

        if source_datastore_id and getattr(source_ds, "_moId", None) != source_datastore_id:
            raise SDRSOperationError("Datastore de origem informado não corresponde à VM selecionada.")

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

        return {
            "cluster_id": cluster_id,
            "cluster_name": MANUAL_CLUSTER_NAME,
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
    datastores, _ = await asyncio.to_thread(_inventory_sync, client)
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
            "cluster_name": MANUAL_CLUSTER_NAME,
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
            "cluster_name": MANUAL_CLUSTER_NAME,
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
            "cluster_name": MANUAL_CLUSTER_NAME,
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
            "cluster_name": MANUAL_CLUSTER_NAME,
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
