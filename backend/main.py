from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from schemas import (
    ClusterCapability,
    ClusterConfig,
    ClusterDerivedDetail,
    ClusterDetailResponse,
    ClusterInsightItem,
    ClusterInsightsResponse,
    ClusterOverviewItem,
    ClusterOverviewResponse,
    ClusterRiskResponse,
    ClusterSnapshot,
    ClusterSuitability,
    ClusterTrendsResponse,
    ClusterTrendsSeries,
    ConstraintImpactItem,
    DashboardSnapshot,
    DatastoreMetricsItem,
    DatastoreMetricsResponse,
    GlobalSnapshot,
    MaintenanceDatastoreItem,
    NearFullDatastoreItem,
    PendingRecommendationItem,
    PendingRecommendationsResponse,
    PendingRecommendationsSummary,
    RecommendationReasonBreakdown,
    RecommendationStatsResponse,
    RecommendationWindowCounts,
    RecommendationsByReason,
    SnapshotAlert,
)
from sdrs import (
    FORBIDDEN_VM_MUTATION_OPERATIONS,
    SDRSOperationError,
    diagnose_latency_collection,
    get_cluster_detail,
    get_move_options_for_vm,
    get_move_candidates,
    get_simulated_move_plan,
    get_pending_recommendations,
    get_task_status,
    list_datastore_vms,
    list_clusters,
    move_vm_to_datastore,
    _invalidate_si,
)
from vcenter import VCenterClient, VCenterClientError, load_secondary_vcenter_configs

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)

logger = logging.getLogger("sdrs-manager")


def _parse_bool_env(name: str, default: bool = True) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _parse_float_env(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except Exception:
        return default


def _parse_int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except Exception:
        return default


def _parse_csv_env(name: str, default: list[str]) -> list[str]:
    value = os.getenv(name)
    if value is None:
        return list(default)

    items = [item.strip() for item in value.split(",")]
    normalized = [item for item in items if item]
    return normalized or list(default)


READ_ONLY_MODE = _parse_bool_env("READ_ONLY_MODE", default=True)
HISTORY_RETENTION_HOURS = max(24, _parse_int_env("ANALYTICS_HISTORY_RETENTION_HOURS", 24 * 30))
ROOT_DIR = Path(__file__).resolve().parent.parent
AUDIT_HISTORY_MAX_ITEMS = max(100, _parse_int_env("AUDIT_HISTORY_MAX_ITEMS", 5000))
AUDIT_HISTORY_FILE = Path(
    (os.getenv("AUDIT_HISTORY_FILE") or str(ROOT_DIR / ".runtime" / "operation_history.jsonl")).strip()
)
_AUDIT_HISTORY_LOCK = threading.RLock()
ALLOW_VM_STORAGE_MOVE = _parse_bool_env("ALLOW_VM_STORAGE_MOVE", default=True)
WRITE_ADMIN_KEY = (os.getenv("WRITE_ADMIN_KEY") or "").strip()
READ_ONLY_TOGGLE_KEY = (os.getenv("READ_ONLY_TOGGLE_KEY") or WRITE_ADMIN_KEY or "").strip()
READ_ONLY_TOGGLE_OPEN = _parse_bool_env("READ_ONLY_TOGGLE_OPEN", default=True)

DEFAULT_CORS_ORIGINS = [
    "http://127.0.0.1:5500",
    "http://localhost:5500",
    "http://127.0.0.1:5501",
    "http://localhost:5501",
]
CORS_ALLOW_ORIGINS = _parse_csv_env("CORS_ALLOW_ORIGINS", DEFAULT_CORS_ORIGINS)
CORS_ALLOW_CREDENTIALS = _parse_bool_env("CORS_ALLOW_CREDENTIALS", default=False)
if "*" in CORS_ALLOW_ORIGINS and CORS_ALLOW_CREDENTIALS:
    logger.warning(
        "CORS_ALLOW_ORIGINS contém '*' com CORS_ALLOW_CREDENTIALS=true. "
        "Forçando credentials=false para evitar bloqueio de CORS no navegador."
    )
    CORS_ALLOW_CREDENTIALS = False


class VCenterConfigPayload(BaseModel):
    host: str = Field(min_length=1)
    user: str = Field(min_length=1)
    password: str = Field(min_length=1)
    verify_ssl: bool = True


class VmMovePayload(BaseModel):
    target_datastore_id: str = Field(min_length=1)
    source_datastore_id: str | None = None


class ReadOnlyModePayload(BaseModel):
    read_only: bool


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.vcenter_client = None
    app.state.vcenter_client_error = None
    app.state.vcenter_config = None
    app.state.secondary_vcenter_warnings = []
    app.state.read_only_mode = READ_ONLY_MODE
    app.state.analytics_history = {"clusters": {}, "datastores": {}}
    app.state.operation_history = _load_audit_history_from_disk(AUDIT_HISTORY_MAX_ITEMS)

    try:
        client = VCenterClient()
        app.state.vcenter_client = client
        logger.info("VCenterClient compartilhado criado com sucesso")
        app.state.vcenter_config = {
            "host": client.host,
            "user": client.user,
            "verify_ssl": client.verify_ssl,
            "source": "env",
        }
    except VCenterClientError as exc:
        app.state.vcenter_client_error = str(exc)
        logger.warning("VCenterClient não inicializado na subida da aplicação: %s", exc)
    except Exception:
        app.state.vcenter_client_error = "Erro inesperado ao inicializar o cliente do vCenter."
        logger.exception("Falha inesperada ao inicializar VCenterClient")

    _record_operation_event_app(
        app,
        action="backend_startup",
        status_text="ok",
        details={
            "read_only_mode": app.state.read_only_mode,
            "vcenter_initialized": app.state.vcenter_client is not None,
            "history_file": str(_history_file_path()),
        },
    )

    # Pre-aquece o cache de inventário em background para que a primeira requisição seja rápida
    async def _warm_inventory_cache() -> None:
        warmup_client = getattr(app.state, "vcenter_client", None)
        if warmup_client is None:
            return
        try:
            logger.info("Iniciando pre-aquecimento do cache de inventário vCenter...")
            await list_clusters(warmup_client)
            logger.info("Cache de inventário pre-aquecido com sucesso.")
        except Exception as exc:
            logger.warning("Falha no pre-aquecimento do cache: %s", exc)

    asyncio.ensure_future(_warm_inventory_cache())

    secondary_cfgs, secondary_warnings = load_secondary_vcenter_configs()
    app.state.secondary_vcenter_warnings = list(secondary_warnings)
    for cfg in secondary_cfgs:
        secondary_client: VCenterClient | None = None
        try:
            secondary_client = VCenterClient(
                host=cfg.host,
                user=cfg.user,
                password=cfg.password,
                verify_ssl=cfg.verify_ssl,
                load_env_file=False,
            )
            await secondary_client.authenticate()
            logger.info("vCenter secundário validado com sucesso: %s", cfg.name)
        except Exception as exc:
            warning = f"vCenter secundário '{cfg.name}' indisponível: {exc}"
            app.state.secondary_vcenter_warnings.append(warning)
            logger.warning(warning)
        finally:
            if secondary_client is not None:
                try:
                    await secondary_client.close()
                except Exception:
                    logger.debug("Falha ao encerrar cliente secundário %s", cfg.name, exc_info=True)

    yield

    _record_operation_event_app(
        app,
        action="backend_shutdown",
        status_text="ok",
        details={"read_only_mode": bool(getattr(app.state, "read_only_mode", True))},
    )

    client = getattr(app.state, "vcenter_client", None)
    if client is not None:
        try:
            await client.close()
        except Exception:
            logger.exception("Erro ao finalizar VCenterClient no shutdown")


app = FastAPI(
    title="SDRS Manager API",
    description="API para monitoramento e gerenciamento de Storage DRS no VMware vCenter.",
    version="0.4.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOW_ORIGINS,
    allow_credentials=CORS_ALLOW_CREDENTIALS,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _json_safe(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    return str(value)


def _history_file_path() -> Path:
    return AUDIT_HISTORY_FILE


def _load_audit_history_from_disk(max_items: int) -> list[dict[str, Any]]:
    path = _history_file_path()
    if not path.exists():
        return []

    entries: list[dict[str, Any]] = []
    try:
        for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw_line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except Exception:
                continue
            if isinstance(parsed, dict):
                entries.append(parsed)
    except Exception:
        logger.warning("Falha ao carregar histórico de operações em %s", path, exc_info=True)
        return []

    if len(entries) > max_items:
        entries = entries[-max_items:]
    return entries


def _append_audit_entry(app: FastAPI, entry: dict[str, Any]) -> None:
    with _AUDIT_HISTORY_LOCK:
        store = getattr(app.state, "operation_history", None)
        if not isinstance(store, list):
            store = []
            app.state.operation_history = store
        store.append(entry)
        if len(store) > AUDIT_HISTORY_MAX_ITEMS:
            del store[: len(store) - AUDIT_HISTORY_MAX_ITEMS]

        path = _history_file_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as fp:
                fp.write(json.dumps(entry, ensure_ascii=False))
                fp.write("\n")
        except Exception:
            logger.warning("Falha ao persistir evento no histórico em %s", path, exc_info=True)


def _record_operation_event(
    request: Request,
    action: str,
    status_text: str = "ok",
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    entry = {
        "ts": _utc_now().isoformat(),
        "action": str(action or "unknown"),
        "status": str(status_text or "unknown"),
        "method": str(getattr(request, "method", "") or ""),
        "path": str(getattr(getattr(request, "url", None), "path", "") or ""),
        "client_ip": str(getattr(getattr(request, "client", None), "host", "") or ""),
        "details": _json_safe(details or {}),
    }
    _append_audit_entry(request.app, entry)
    return entry


def _record_operation_event_app(
    app: FastAPI,
    action: str,
    status_text: str = "ok",
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    entry = {
        "ts": _utc_now().isoformat(),
        "action": str(action or "unknown"),
        "status": str(status_text or "unknown"),
        "method": "",
        "path": "",
        "client_ip": "",
        "details": _json_safe(details or {}),
    }
    _append_audit_entry(app, entry)
    return entry


async def _replace_vcenter_client(
    request: Request,
    new_client: VCenterClient | None,
    init_error: str | None,
    config: dict[str, Any] | None,
) -> None:
    old_client = getattr(request.app.state, "vcenter_client", None)

    request.app.state.vcenter_client = new_client
    request.app.state.vcenter_client_error = init_error
    request.app.state.vcenter_config = config

    if old_client is not None:
        try:
            _invalidate_si(old_client)
        except Exception:
            pass
        try:
            await old_client.close()
        except Exception:
            logger.exception("Erro ao fechar cliente antigo do vCenter durante troca de configuração")


def _is_read_only_mode(request: Request) -> bool:
    return bool(getattr(request.app.state, "read_only_mode", True))


def _get_move_guardrails() -> dict[str, Any]:
    return {
        "min_free_headroom_pct": _parse_float_env("MOVE_MIN_FREE_HEADROOM_PCT", 15.0),
        "min_vm_reserve_ratio": _parse_float_env("MOVE_MIN_VM_RESERVE_RATIO", 0.10),
        "max_target_used_pct": _parse_float_env("MOVE_MAX_TARGET_USED_PCT", 95.0),
        "max_concurrent_per_cluster": _parse_int_env("MOVE_MAX_CONCURRENT_PER_CLUSTER", 2),
    }


def _get_safety_policy(request: Request) -> dict[str, Any]:
    read_only_toggle_key_required = (not READ_ONLY_TOGGLE_OPEN) and bool(READ_ONLY_TOGGLE_KEY)
    return {
        "read_only_mode": _is_read_only_mode(request),
        "allow_vm_storage_move": ALLOW_VM_STORAGE_MOVE,
        "write_admin_key_required": bool(WRITE_ADMIN_KEY),
        "read_only_toggle_key_required": read_only_toggle_key_required,
        "read_only_toggle_open": READ_ONLY_TOGGLE_OPEN,
        "operation_history_enabled": True,
        "move_confirmation_header_required": True,
        "forbid_vm_delete": True,
        "forbid_vm_power_actions": True,
        "forbid_vm_reconfigure": True,
        "forbid_recommendation_apply_dismiss": True,
        "allowed_write_operations": ["vm_storage_relocate"],
        "blocked_vm_operations": list(FORBIDDEN_VM_MUTATION_OPERATIONS),
    }


def _require_admin_key_if_configured(request: Request) -> None:
    if not WRITE_ADMIN_KEY:
        return

    provided = (request.headers.get("x-admin-key") or "").strip()
    if provided != WRITE_ADMIN_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Cabeçalho X-Admin-Key ausente ou inválido.",
        )


def _is_loopback_request(request: Request) -> bool:
    client = getattr(request, "client", None)
    host = str(getattr(client, "host", "") or "").strip().lower()
    return host in {"127.0.0.1", "::1", "localhost"}


def _authorize_read_only_toggle(request: Request) -> None:
    # Fluxo default para operação local: toggle sem chave.
    if READ_ONLY_TOGGLE_OPEN:
        if not _is_loopback_request(request):
            _record_operation_event(
                request,
                action="read_only_toggle",
                status_text="denied",
                details={"reason": "non_loopback_in_open_mode"},
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Alternância read-only aberta apenas para acesso local (loopback).",
            )
        return

    if not READ_ONLY_TOGGLE_KEY:
        _record_operation_event(
            request,
            action="read_only_toggle",
            status_text="denied",
            details={"reason": "missing_toggle_key_configuration"},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Alternância de read-only protegida por chave, mas sem chave configurada. "
                "Defina READ_ONLY_TOGGLE_KEY ou habilite READ_ONLY_TOGGLE_OPEN=true."
            ),
        )

    provided = (request.headers.get("x-readonly-key") or "").strip()
    if provided != READ_ONLY_TOGGLE_KEY:
        _record_operation_event(
            request,
            action="read_only_toggle",
            status_text="denied",
            details={"reason": "invalid_readonly_key"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Cabeçalho X-Readonly-Key ausente ou inválido.",
        )


def get_vcenter_client(request: Request) -> VCenterClient:
    client = getattr(request.app.state, "vcenter_client", None)
    init_error = getattr(request.app.state, "vcenter_client_error", None)

    if client is not None:
        return client

    detail = init_error or "Cliente do vCenter não está disponível."
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=detail,
    )


def _map_vcenter_error(exc: VCenterClientError) -> HTTPException:
    message = str(exc).lower()

    if "autenticação" in message or "acesso negado" in message:
        return HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        )

    if "timeout" in message:
        return HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=str(exc),
        )

    if "não foi possível conectar" in message or "erro de comunicação" in message:
        return HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(exc),
        )

    return HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=str(exc),
    )


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except Exception:
        return default


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _history_cutoff(now: datetime) -> datetime:
    return now - timedelta(hours=HISTORY_RETENTION_HOURS)


def _get_history_store(request: Request) -> dict[str, Any]:
    store = getattr(request.app.state, "analytics_history", None)
    if not isinstance(store, dict):
        store = {"clusters": {}, "datastores": {}}
        request.app.state.analytics_history = store
    if "clusters" not in store:
        store["clusters"] = {}
    if "datastores" not in store:
        store["datastores"] = {}
    return store


def _prune_points(points: list[dict[str, Any]], cutoff: datetime) -> None:
    if not points:
        return
    while points and isinstance(points[0].get("ts"), datetime) and points[0]["ts"] < cutoff:
        points.pop(0)


def _append_history_point(points: list[dict[str, Any]], point: dict[str, Any], cutoff: datetime) -> None:
    points.append(point)
    _prune_points(points, cutoff)


def _capture_cluster_history(
    request: Request,
    cluster_id: str,
    derived: ClusterDerivedDetail,
    metrics: DatastoreMetricsResponse,
    pending_count: int,
) -> None:
    now = _utc_now()
    cutoff = _history_cutoff(now)
    store = _get_history_store(request)
    cluster_store: dict[str, list[dict[str, Any]]] = store["clusters"]
    ds_store: dict[str, list[dict[str, Any]]] = store["datastores"]

    cluster_points = cluster_store.setdefault(cluster_id, [])
    _append_history_point(
        cluster_points,
        {
            "ts": now,
            "avg_used_percent": float(derived.avg_used_percent),
            "space_imbalance_percent": float(derived.space_imbalance_percent),
            "worst_p90_latency_ms": float(derived.worst_p90_latency_ms or 0.0),
            "latency_overload_ratio": float(derived.latency_overload_ratio or 0.0),
            "total_free_gb": float(derived.total_free_gb),
            "pending_count": int(pending_count),
        },
        cutoff,
    )

    for item in metrics.items:
        ds_key = f"{cluster_id}::{item.datastore_id}"
        ds_points = ds_store.setdefault(ds_key, [])
        _append_history_point(
            ds_points,
            {
                "ts": now,
                "used_percent": float(item.used_percent),
                "free_space_gb": float(item.free_space_gb),
                "p90_latency_ms": float(item.p90_latency_ms or 0.0),
            },
            cutoff,
        )


def _cluster_history_points(request: Request, cluster_id: str) -> list[dict[str, Any]]:
    store = _get_history_store(request)
    cluster_store: dict[str, list[dict[str, Any]]] = store["clusters"]
    points = list(cluster_store.get(cluster_id, []))
    points.sort(key=lambda x: x.get("ts") or datetime.min.replace(tzinfo=timezone.utc))
    return points


def _datastore_history_map(request: Request, cluster_id: str) -> dict[str, list[dict[str, Any]]]:
    store = _get_history_store(request)
    ds_store: dict[str, list[dict[str, Any]]] = store["datastores"]
    result: dict[str, list[dict[str, Any]]] = {}
    prefix = f"{cluster_id}::"
    for key, points in ds_store.items():
        if not key.startswith(prefix):
            continue
        ds_id = key[len(prefix) :]
        ordered = list(points)
        ordered.sort(key=lambda x: x.get("ts") or datetime.min.replace(tzinfo=timezone.utc))
        result[ds_id] = ordered
    return result


def _compute_growth_from_free_series(
    points: list[dict[str, Any]],
    current_free_gb: float,
    capacity_gb: float,
) -> tuple[float | None, float | None, float | None]:
    if len(points) < 2:
        return None, None, None

    first = points[0]
    last = points[-1]
    first_ts = first.get("ts")
    last_ts = last.get("ts")
    if not isinstance(first_ts, datetime) or not isinstance(last_ts, datetime):
        return None, None, None

    delta_days = (last_ts - first_ts).total_seconds() / 86400.0
    if delta_days <= 0.0035:  # ~5 minutos
        return None, None, None

    first_free = _as_float(first.get("free_space_gb"), default=float(current_free_gb))
    last_free = _as_float(last.get("free_space_gb"), default=float(current_free_gb))
    growth_gb_per_day = (first_free - last_free) / delta_days
    growth_gb_per_day = round(growth_gb_per_day, 2)

    if capacity_gb <= 0:
        return growth_gb_per_day, None, None

    growth_pct_per_day = round((growth_gb_per_day / capacity_gb) * 100.0, 3)
    days_to_full: float | None = None
    if growth_gb_per_day > 0.01:
        days_to_full = round(max(0.0, current_free_gb / growth_gb_per_day), 2)

    return growth_gb_per_day, growth_pct_per_day, days_to_full


def _apply_cluster_growth_from_history(
    derived: ClusterDerivedDetail,
    cluster_history: list[dict[str, Any]],
) -> ClusterDerivedDetail:
    if len(cluster_history) < 2:
        return derived

    series = [
        {
            "ts": point.get("ts"),
            "free_space_gb": point.get("total_free_gb"),
        }
        for point in cluster_history
    ]
    growth_gb_day, _, days_to_full = _compute_growth_from_free_series(
        series,
        current_free_gb=float(derived.total_free_gb),
        capacity_gb=float(derived.total_capacity_gb),
    )

    return derived.model_copy(
        update={
            "cluster_growth_rate_gb_per_day": growth_gb_day,
            "cluster_days_to_full": days_to_full,
        }
    )


def _normalize_automation_level(sdrs_enabled: bool, raw_level: str | None) -> str:
    if not sdrs_enabled:
        return "disabled"
    level = (raw_level or "").strip().lower()
    if "auto" in level:
        return "automated"
    return "manual"


def _map_reason_type(reason: str | None, rec_type: str | None) -> str:
    text = f"{reason or ''} {rec_type or ''}".lower()
    if "space" in text:
        return "space_balance"
    if "latency" in text or "io" in text:
        return "latency_balance"
    if "maintenance" in text or "evac" in text:
        return "maintenance_evacuation"
    if "rule" in text:
        return "rule_correction"
    return "other"


def _build_cluster_config(summary: dict[str, Any], detail: dict[str, Any]) -> ClusterConfig:
    return ClusterConfig(
        cluster_id=str(summary.get("id", "")),
        name=str(summary.get("name", "unknown")),
        sdrs_enabled=bool(summary.get("sdrs_enabled", False)),
        automation_level=_normalize_automation_level(
            bool(summary.get("sdrs_enabled", False)),
            summary.get("sdrs_automation_level"),
        ),
        space_threshold_percent=80.0,
        sdrs_latency_threshold_ms=_as_float(summary.get("io_latency_threshold"), default=0.0)
        if summary.get("io_latency_threshold") is not None
        else None,
        sioc_congestion_threshold_ms=None,
        io_metric_enabled=True if summary.get("io_latency_threshold") is not None else None,
        capabilities=ClusterCapability(
            io_load_balancing_supported=True,
            maintenance_mode_supported=True,
            rule_inspection_supported=True,
        ),
    )


def _build_cluster_derived(detail: dict[str, Any], config: ClusterConfig) -> ClusterDerivedDetail:
    datastores = list(detail.get("datastores", []) or [])

    capacities = [_as_float(ds.get("capacity_gb")) for ds in datastores]
    free_spaces = [_as_float(ds.get("free_gb")) for ds in datastores]
    used_values = [_as_float(ds.get("used_pct")) for ds in datastores if ds.get("used_pct") is not None]
    latencies = [_as_float(ds.get("latency_ms")) for ds in datastores if ds.get("latency_ms") is not None]

    total_capacity = round(sum(capacities), 2)
    total_free = round(sum(free_spaces), 2)
    avg_used = round(sum(used_values) / len(used_values), 2) if used_values else 0.0
    max_used = round(max(used_values), 2) if used_values else 0.0
    min_used = round(min(used_values), 2) if used_values else 0.0
    space_imbalance = round(max_used - min_used, 2) if used_values else 0.0

    avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else None
    worst_latency = round(max(latencies), 2) if latencies else None

    overload_ratio = None
    if latencies and config.sdrs_latency_threshold_ms and config.sdrs_latency_threshold_ms > 0:
        above = len([x for x in latencies if x >= config.sdrs_latency_threshold_ms])
        overload_ratio = round(above / len(latencies), 2)

    if max_used >= 90 or (overload_ratio is not None and overload_ratio >= 0.5):
        health = "critical"
    elif max_used >= 80 or (overload_ratio is not None and overload_ratio >= 0.1):
        health = "warning"
    else:
        health = "healthy"

    return ClusterDerivedDetail(
        total_capacity_gb=total_capacity,
        total_free_gb=total_free,
        avg_used_percent=avg_used,
        max_used_percent=max_used,
        min_used_percent=min_used,
        space_imbalance_percent=space_imbalance,
        space_imbalance_index=round(space_imbalance / 2.7, 2) if space_imbalance else 0.0,
        cluster_growth_rate_gb_per_day=None,
        cluster_days_to_full=None,
        avg_p90_latency_ms=avg_latency,
        worst_p90_latency_ms=worst_latency,
        latency_overload_ratio=overload_ratio,
        performance_health=health,
        backend_overloaded_flag=(health == "critical"),
    )


def _build_cluster_suitability(detail: dict[str, Any], derived: ClusterDerivedDetail) -> ClusterSuitability:
    datastore_count = int(detail.get("datastore_count", len(detail.get("datastores", []) or [])))
    max_datastores = 64
    max_vmdks = 9000
    near_max = datastore_count >= int(max_datastores * 0.9)

    score = 100
    if derived.performance_health == "warning":
        score -= 10
    if derived.performance_health == "critical":
        score -= 20
    if near_max:
        score -= 10
    score = max(0, min(100, score))

    badges: list[str] = ["Homogeneous / OK"]
    warnings: list[str] = []
    if derived.space_imbalance_percent > 20:
        warnings.append("Space imbalance elevado")
    if derived.latency_overload_ratio is not None and derived.latency_overload_ratio > 0.1:
        warnings.append("Latência acima do threshold em parte dos datastores")
    if not near_max:
        badges.append("Full connectivity")
    else:
        warnings.append("Cluster próximo dos limites de configuração")

    return ClusterSuitability(
        score=score,
        protocol_consistent=True,
        media_type_consistent=True,
        performance_class_consistent=None,
        full_host_connectivity=True,
        host_visibility_ratio=1.0,
        mixed_reason=[],
        datastore_count=datastore_count,
        vmdk_count=None,
        max_datastores=max_datastores,
        max_vmdks=max_vmdks,
        near_config_maximums=near_max,
        badges=badges,
        warnings=warnings,
    )


def _build_datastore_metrics(
    cluster_id: str,
    detail: dict[str, Any],
    config: ClusterConfig,
    history_by_datastore: dict[str, list[dict[str, Any]]] | None = None,
) -> DatastoreMetricsResponse:
    items: list[DatastoreMetricsItem] = []
    history_by_datastore = history_by_datastore or {}
    for ds in list(detail.get("datastores", []) or []):
        ds_id = str(ds.get("id", ""))
        used = _as_float(ds.get("used_pct"))
        capacity_gb = _as_float(ds.get("capacity_gb"))
        free_gb = _as_float(ds.get("free_gb"))
        latency = _as_float(ds.get("latency_ms")) if ds.get("latency_ms") is not None else None
        near_latency = (
            latency is not None
            and config.sdrs_latency_threshold_ms is not None
            and latency >= (config.sdrs_latency_threshold_ms * 0.9)
        )
        above_latency = (
            latency is not None
            and config.sdrs_latency_threshold_ms is not None
            and latency >= config.sdrs_latency_threshold_ms
        )

        growth_gb_day, growth_pct_day, days_to_full = _compute_growth_from_free_series(
            history_by_datastore.get(ds_id, []),
            current_free_gb=free_gb,
            capacity_gb=capacity_gb,
        )

        items.append(
            DatastoreMetricsItem(
                datastore_id=ds_id,
                name=str(ds.get("name", "unknown")),
                total_capacity_gb=capacity_gb,
                free_space_gb=free_gb,
                used_percent=used,
                above_space_threshold=used >= config.space_threshold_percent,
                critical_used_percent=used >= 90.0,
                growth_rate_gb_per_day=growth_gb_day,
                growth_rate_percent_per_day=growth_pct_day,
                days_to_full=days_to_full,
                avg_read_latency_ms=latency,
                avg_write_latency_ms=latency,
                p90_latency_ms=latency,
                iops_read=None,
                iops_write=None,
                throughput_read_mb_s=None,
                throughput_write_mb_s=None,
                near_latency_threshold=near_latency,
                above_latency_threshold=above_latency,
                maintenance_requested=False,
                evacuation_progress_percent=None,
            )
        )

    return DatastoreMetricsResponse(items=items)


def _build_pending_recommendations(cluster_id: str, recs: list[dict[str, Any]]) -> PendingRecommendationsResponse:
    pending: list[PendingRecommendationItem] = []
    space_count = 0
    latency_count = 0
    maintenance_count = 0

    for rec in recs:
        reason_type = _map_reason_type(rec.get("reason"), rec.get("type"))
        if reason_type == "space_balance":
            space_count += 1
        elif reason_type == "latency_balance":
            latency_count += 1
        elif reason_type == "maintenance_evacuation":
            maintenance_count += 1

        pending.append(
            PendingRecommendationItem(
                recommendation_key=str(rec.get("key", "")),
                reason_type=reason_type,
                status="pending",
                vm_name=rec.get("vm_name"),
                source_datastore_id=rec.get("source_ds"),
                target_datastore_id=rec.get("target_ds"),
                size_gb=_as_float(rec.get("size_gb")) if rec.get("size_gb") is not None else None,
                created_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            )
        )

    return PendingRecommendationsResponse(
        pending=pending,
        summary=PendingRecommendationsSummary(
            pending_count=len(pending),
            space_balance_count=space_count,
            latency_balance_count=latency_count,
            maintenance_evacuation_count=maintenance_count,
        ),
    )


def _build_recommendation_stats(pending_payload: PendingRecommendationsResponse) -> RecommendationStatsResponse:
    generated = pending_payload.summary.pending_count
    applied = 0
    dismissed = 0
    failed = 0
    expired = 0

    acceptance_rate = round(applied / generated, 2) if generated > 0 else 0.0
    patterns: list[str] = []
    if pending_payload.summary.latency_balance_count > pending_payload.summary.space_balance_count:
        patterns.append("Latency recommendations are dominating current pending queue")
    else:
        patterns.append("Space recommendations are dominating current pending queue")

    return RecommendationStatsResponse(
        window="30d",
        counts=RecommendationWindowCounts(
            generated=generated,
            applied=applied,
            dismissed=dismissed,
            failed=failed,
            expired=expired,
        ),
        by_reason=RecommendationsByReason(
            space_balance=RecommendationReasonBreakdown(
                generated=pending_payload.summary.space_balance_count,
                applied=0,
                dismissed=0,
            ),
            latency_balance=RecommendationReasonBreakdown(
                generated=pending_payload.summary.latency_balance_count,
                applied=0,
                dismissed=0,
            ),
            maintenance_evacuation=RecommendationReasonBreakdown(
                generated=pending_payload.summary.maintenance_evacuation_count,
                applied=0,
                dismissed=0,
            ),
        ),
        acceptance_rate=acceptance_rate,
        avg_space_imbalance_delta=None,
        avg_latency_delta_ms=None,
        patterns=patterns,
    )


def _build_trends(
    derived: ClusterDerivedDetail,
    pending_payload: PendingRecommendationsResponse,
    cluster_history: list[dict[str, Any]] | None = None,
) -> ClusterTrendsResponse:
    cluster_history = cluster_history or []
    by_day: dict[str, dict[str, Any]] = {}

    for point in cluster_history:
        ts = point.get("ts")
        if not isinstance(ts, datetime):
            continue
        day = ts.date().isoformat()
        bucket = by_day.setdefault(
            day,
            {
                "count": 0,
                "avg_used_sum": 0.0,
                "imbalance_sum": 0.0,
                "overload_sum": 0.0,
                "worst_latency": 0.0,
                "pending_count": 0,
            },
        )
        bucket["count"] += 1
        bucket["avg_used_sum"] += _as_float(point.get("avg_used_percent"))
        bucket["imbalance_sum"] += _as_float(point.get("space_imbalance_percent"))
        bucket["overload_sum"] += _as_float(point.get("latency_overload_ratio"))
        bucket["worst_latency"] = max(bucket["worst_latency"], _as_float(point.get("worst_p90_latency_ms")))
        bucket["pending_count"] = int(_as_float(point.get("pending_count"), default=float(bucket["pending_count"])))

    if not by_day:
        today = datetime.now(timezone.utc).date().isoformat()
        pending = int(pending_payload.summary.pending_count)
        by_day[today] = {
            "count": 1,
            "avg_used_sum": float(derived.avg_used_percent),
            "imbalance_sum": float(derived.space_imbalance_percent),
            "overload_sum": float(derived.latency_overload_ratio or 0.0),
            "worst_latency": float(derived.worst_p90_latency_ms or 0.0),
            "pending_count": pending,
        }

    ordered_days = sorted(by_day.keys())
    avg_used_series: list[tuple[str, float]] = []
    imbalance_series: list[tuple[str, float]] = []
    worst_latency_series: list[tuple[str, float]] = []
    overload_series: list[tuple[str, float]] = []
    generated_series: list[tuple[str, int]] = []
    applied_series: list[tuple[str, int]] = []

    previous_pending: int | None = None
    for day in ordered_days:
        bucket = by_day[day]
        count = max(1, int(bucket["count"]))
        pending = int(bucket["pending_count"])

        avg_used = round(float(bucket["avg_used_sum"]) / count, 2)
        imbalance = round(float(bucket["imbalance_sum"]) / count, 2)
        worst_latency = round(float(bucket["worst_latency"]), 2)
        overload = round(float(bucket["overload_sum"]) / count, 3)

        if previous_pending is None:
            generated = max(0, pending)
            applied = 0
        else:
            delta = pending - previous_pending
            generated = max(0, delta)
            applied = max(0, -delta)
        previous_pending = pending

        avg_used_series.append((day, avg_used))
        imbalance_series.append((day, imbalance))
        worst_latency_series.append((day, worst_latency))
        overload_series.append((day, overload))
        generated_series.append((day, generated))
        applied_series.append((day, applied))

    return ClusterTrendsResponse(
        window="30d",
        resolution="1d",
        series=ClusterTrendsSeries(
            avg_used_percent=avg_used_series,
            space_imbalance_percent=imbalance_series,
            worst_p90_latency_ms=worst_latency_series,
            latency_overload_ratio=overload_series,
            recommendations_generated=generated_series,
            recommendations_applied=applied_series,
        ),
    )


def _build_cluster_risk(
    cluster_id: str,
    metrics: DatastoreMetricsResponse,
    pending_payload: PendingRecommendationsResponse,
) -> ClusterRiskResponse:
    near_full: list[NearFullDatastoreItem] = []
    maintenance: list[MaintenanceDatastoreItem] = []

    pending_by_source: dict[str, int] = {}
    for rec in pending_payload.pending:
        if rec.source_datastore_id:
            pending_by_source[rec.source_datastore_id] = pending_by_source.get(rec.source_datastore_id, 0) + 1

    for item in metrics.items:
        if item.used_percent >= 85:
            near_full.append(
                NearFullDatastoreItem(
                    datastore_id=item.datastore_id,
                    name=item.name,
                    used_percent=item.used_percent,
                    days_to_full=item.days_to_full,
                    sdrs_recommendations_pending=pending_by_source.get(item.datastore_id, 0),
                )
            )
        if item.maintenance_requested:
            maintenance.append(
                MaintenanceDatastoreItem(
                    datastore_id=item.datastore_id,
                    name=item.name,
                    maintenance_requested=True,
                    migrated_vmdks=0,
                    total_vmdks=0,
                    progress_percent=item.evacuation_progress_percent or 0.0,
                )
            )

    near_full.sort(
        key=lambda item: (
            1 if item.used_percent >= 90 else 0,
            1 if (item.days_to_full is not None and item.days_to_full <= 30) else 0,
            item.sdrs_recommendations_pending,
            item.used_percent,
            0.0 if item.days_to_full is None else (365.0 - min(365.0, item.days_to_full)),
        ),
        reverse=True,
    )

    return ClusterRiskResponse(
        near_full=near_full,
        maintenance=maintenance,
        constraints=[],
    )


def _build_cluster_overview_item(
    summary: dict[str, Any],
    config: ClusterConfig,
    derived: ClusterDerivedDetail,
    suitability: ClusterSuitability,
    metrics: DatastoreMetricsResponse,
    pending_payload: PendingRecommendationsResponse,
) -> ClusterOverviewItem:
    near_threshold_count = len([x for x in metrics.items if x.above_space_threshold or x.near_latency_threshold])
    return ClusterOverviewItem(
        cluster_id=str(summary.get("id", "")),
        name=str(summary.get("name", "unknown")),
        sdrs_enabled=bool(summary.get("sdrs_enabled", False)),
        automation_level=config.automation_level,
        space_threshold_percent=config.space_threshold_percent,
        latency_threshold_ms=config.sdrs_latency_threshold_ms,
        total_capacity_gb=derived.total_capacity_gb,
        total_free_gb=derived.total_free_gb,
        avg_used_percent=derived.avg_used_percent,
        space_imbalance_percent=derived.space_imbalance_percent,
        worst_p90_latency_ms=derived.worst_p90_latency_ms,
        datastores_near_threshold=near_threshold_count,
        pending_recommendations=pending_payload.summary.pending_count,
        suitability_score=suitability.score,
        badges=suitability.badges,
    )


def _build_cluster_snapshot(
    summary: dict[str, Any],
    config: ClusterConfig,
    derived: ClusterDerivedDetail,
    suitability: ClusterSuitability,
    pending_payload: PendingRecommendationsResponse,
) -> ClusterSnapshot:
    if derived.performance_health == "critical":
        risk_level = "critical"
    elif derived.performance_health == "warning":
        risk_level = "warning"
    else:
        risk_level = "healthy"

    return ClusterSnapshot(
        cluster_id=str(summary.get("id", "")),
        name=str(summary.get("name", "unknown")),
        sdrs_enabled=bool(summary.get("sdrs_enabled", False)),
        automation_level=config.automation_level,
        total_free_gb=derived.total_free_gb,
        avg_used_percent=derived.avg_used_percent,
        space_imbalance_percent=derived.space_imbalance_percent,
        space_imbalance_index=derived.space_imbalance_index,
        worst_p90_latency_ms=derived.worst_p90_latency_ms,
        latency_overload_ratio=derived.latency_overload_ratio,
        performance_health=derived.performance_health,
        suitability_score=suitability.score,
        pending_recommendations=pending_payload.summary.pending_count,
        risk_level=risk_level,
    )


def _build_insight_item(
    summary: dict[str, Any],
    config: ClusterConfig,
    derived: ClusterDerivedDetail,
    suitability: ClusterSuitability,
    pending_payload: PendingRecommendationsResponse,
) -> ClusterInsightItem:
    diagnosis: list[str] = []
    if suitability.score >= 85:
        diagnosis.append("Good suitability")
    elif suitability.score >= 70:
        diagnosis.append("Reasonable suitability")
    else:
        diagnosis.append("Low suitability")

    if derived.space_imbalance_percent >= 20:
        diagnosis.append("High space imbalance")
    elif derived.space_imbalance_percent >= 10:
        diagnosis.append("Moderate space imbalance")
    else:
        diagnosis.append("Balanced space usage")

    if (derived.latency_overload_ratio or 0.0) > 0.1:
        diagnosis.append("Latency occasionally exceeds threshold")

    if config.automation_level == "manual":
        diagnosis.append("Manual mode may slow remediation")

    return ClusterInsightItem(
        cluster_id=str(summary.get("id", "")),
        name=str(summary.get("name", "unknown")),
        score=suitability.score,
        space_imbalance_index=derived.space_imbalance_index,
        latency_overload_ratio=derived.latency_overload_ratio,
        migrations_per_day=None,
        automation_level=config.automation_level,
        diagnosis=diagnosis,
    )


@app.get(
    "/",
    tags=["system"],
    summary="Root endpoint",
    description="Retorna uma mensagem simples indicando que o backend está em execução.",
)
async def root() -> dict[str, str]:
    return {
        "message": "SDRS Manager backend is running",
        "docs": "/docs",
    }


@app.get(
    "/api/health",
    tags=["system"],
    summary="Health check",
    description="Retorna o status do backend e o host do vCenter configurado no ambiente.",
)
async def health(request: Request) -> dict[str, Any]:
    init_error = getattr(request.app.state, "vcenter_client_error", None)
    active_cfg = getattr(request.app.state, "vcenter_config", None) or {}
    secondary_warnings = list(getattr(request.app.state, "secondary_vcenter_warnings", []) or [])

    return {
        "status": "ok",
        "service": "sdrs-manager-backend",
        "vcenter": active_cfg.get("host", ""),
        "client_initialized": getattr(request.app.state, "vcenter_client", None) is not None,
        "client_init_error": init_error,
        "read_only": _is_read_only_mode(request),
        "cors_allow_origins": CORS_ALLOW_ORIGINS,
        "cors_allow_credentials": CORS_ALLOW_CREDENTIALS,
        "move_guardrails": _get_move_guardrails(),
        "safety_policy": _get_safety_policy(request),
        "secondary_vcenter_warnings": secondary_warnings,
    }


@app.get(
    "/api/safety/policy",
    tags=["system"],
    summary="Política de segurança de escrita",
    description="Retorna regras imutáveis: sem exclusão de VM e somente operação de move entre datastores.",
)
async def safety_policy(request: Request) -> dict[str, Any]:
    return _get_safety_policy(request)


@app.get(
    "/api/history",
    tags=["system"],
    summary="Histórico operacional",
    description="Retorna histórico das ações executadas pelo backend (persistido em disco).",
)
async def operation_history(
    request: Request,
    limit: int = Query(default=200, ge=1, le=2000),
    action: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
) -> dict[str, Any]:
    history = list(getattr(request.app.state, "operation_history", []) or [])

    filtered = history
    if action:
        action_norm = str(action).strip().lower()
        filtered = [item for item in filtered if str(item.get("action", "")).lower() == action_norm]
    if status_filter:
        status_norm = str(status_filter).strip().lower()
        filtered = [item for item in filtered if str(item.get("status", "")).lower() == status_norm]

    total = len(filtered)
    items = filtered[-limit:]
    items.reverse()
    return {
        "items": items,
        "count": len(items),
        "total": total,
        "limit": limit,
        "history_file": str(_history_file_path()),
    }


@app.post(
    "/api/safety/read-only",
    tags=["system"],
    summary="Alterna read-only em runtime",
    description=(
        "Atualiza o modo de segurança read-only em memória (não persiste no .env). "
        "Exige cabeçalho X-Readonly-Key."
    ),
)
async def set_read_only_mode(request: Request, payload: ReadOnlyModePayload) -> dict[str, Any]:
    _authorize_read_only_toggle(request)
    previous = _is_read_only_mode(request)
    request.app.state.read_only_mode = bool(payload.read_only)
    current = _is_read_only_mode(request)
    _record_operation_event(
        request,
        action="read_only_toggle",
        status_text="ok",
        details={
            "previous_read_only": previous,
            "current_read_only": current,
            "toggle_open": READ_ONLY_TOGGLE_OPEN,
        },
    )
    return {
        "updated": True,
        "read_only": current,
        "source": "runtime",
    }


@app.post(
    "/api/vcenter/config",
    tags=["config"],
    summary="Define configuração de vCenter em runtime",
    description="Atualiza host/usuário/senha/SSL do cliente em memória (sem persistir no arquivo .env).",
)
async def set_vcenter_config(request: Request, payload: VCenterConfigPayload) -> dict[str, Any]:
    _require_admin_key_if_configured(request)

    try:
        client = VCenterClient(
            host=payload.host,
            user=payload.user,
            password=payload.password,
            verify_ssl=payload.verify_ssl,
            load_env_file=False,
        )
    except VCenterClientError as exc:
        _record_operation_event(
            request,
            action="vcenter_config_set",
            status_text="error",
            details={"host": payload.host, "user": payload.user, "error": str(exc)},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    cfg = {
        "host": client.host,
        "user": client.user,
        "verify_ssl": client.verify_ssl,
        "source": "runtime",
    }
    await _replace_vcenter_client(request, client, None, cfg)

    _record_operation_event(
        request,
        action="vcenter_config_set",
        status_text="ok",
        details={"host": client.host, "user": client.user, "verify_ssl": client.verify_ssl},
    )

    return {
        "configured": True,
        **cfg,
    }


@app.get(
    "/api/vcenter/config",
    tags=["config"],
    summary="Lê configuração de vCenter ativa",
    description="Retorna host/usuário/SSL da configuração em uso atualmente.",
)
async def get_vcenter_config(request: Request) -> dict[str, Any]:
    cfg = getattr(request.app.state, "vcenter_config", None)
    init_error = getattr(request.app.state, "vcenter_client_error", None)

    if not cfg:
        return {
            "configured": False,
            "host": "",
            "user": "",
            "verify_ssl": True,
            "source": "none",
            "client_init_error": init_error,
        }

    return {
        "configured": True,
        "host": cfg.get("host", ""),
        "user": cfg.get("user", ""),
        "verify_ssl": bool(cfg.get("verify_ssl", True)),
        "source": cfg.get("source", "runtime"),
        "client_init_error": init_error,
    }


@app.post(
    "/api/auth/connect",
    tags=["auth"],
    summary="Testa conexão com o vCenter",
    description="Tenta autenticar no vCenter usando as variáveis de ambiente atuais.",
)
async def auth_connect(request: Request) -> dict[str, Any]:
    client = get_vcenter_client(request)

    try:
        await client.authenticate()
        _record_operation_event(
            request,
            action="auth_connect",
            status_text="ok",
            details={"host": client.host},
        )
        return {
            "connected": True,
            "host": client.host,
        }
    except VCenterClientError as exc:
        _record_operation_event(
            request,
            action="auth_connect",
            status_text="error",
            details={"host": client.host, "error": str(exc)},
        )
        raise _map_vcenter_error(exc)
    except Exception:
        logger.exception("Erro inesperado ao testar conexão com o vCenter")
        _record_operation_event(
            request,
            action="auth_connect",
            status_text="error",
            details={"host": client.host, "error": "unexpected_error"},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro inesperado ao conectar ao vCenter.",
        )


@app.get(
    "/api/clusters",
    tags=["clusters"],
    summary="Lista datastore clusters",
    description="Retorna todos os datastore clusters (StoragePod) com resumo do Storage DRS.",
)
async def api_list_clusters(request: Request) -> list[dict[str, Any]]:
    client = get_vcenter_client(request)

    try:
        return await list_clusters(client)
    except VCenterClientError as exc:
        raise _map_vcenter_error(exc)
    except Exception:
        logger.exception("Erro inesperado ao listar datastore clusters")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro inesperado ao listar datastore clusters.",
        )


@app.get(
    "/api/clusters/{cluster_id}",
    tags=["clusters"],
    summary="Detalhe do datastore cluster",
    description="Retorna o resumo e os datastores membros de um datastore cluster específico.",
)
async def api_get_cluster_detail(request: Request, cluster_id: str) -> dict[str, Any]:
    client = get_vcenter_client(request)

    try:
        data = await get_cluster_detail(client, cluster_id)
        if not data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Datastore cluster não encontrado.",
            )
        return data
    except HTTPException:
        raise
    except VCenterClientError as exc:
        raise _map_vcenter_error(exc)
    except Exception:
        logger.exception("Erro inesperado ao obter detalhe do cluster %s", cluster_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro inesperado ao obter detalhe do datastore cluster.",
        )


@app.get(
    "/api/diagnostics/latency",
    tags=["diagnostics"],
    summary="Diagnóstico de coleta de latência",
    description=(
        "Executa diagnóstico técnico de leitura de latência por datastore. "
        "Endpoint somente leitura para identificar indisponibilidade de métrica, "
        "permissão insuficiente ou limitação de coleta no ambiente."
    ),
)
async def api_diagnostics_latency(
    request: Request,
    cluster_id: str | None = None,
    max_datastores: int = Query(default=3, ge=1, le=20),
) -> dict[str, Any]:
    client = get_vcenter_client(request)

    try:
        payload = await diagnose_latency_collection(
            client,
            cluster_id=cluster_id,
            max_datastores_per_cluster=max_datastores,
        )
        _record_operation_event(
            request,
            action="latency_diagnostics",
            status_text="ok",
            details={
                "cluster_id": cluster_id,
                "max_datastores": max_datastores,
                "message": payload.get("message"),
            },
        )
        return payload
    except VCenterClientError as exc:
        _record_operation_event(
            request,
            action="latency_diagnostics",
            status_text="error",
            details={"cluster_id": cluster_id, "error": str(exc)},
        )
        raise _map_vcenter_error(exc)
    except Exception:
        logger.exception("Erro inesperado no diagnóstico de latência")
        _record_operation_event(
            request,
            action="latency_diagnostics",
            status_text="error",
            details={"cluster_id": cluster_id, "error": "unexpected_error"},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro inesperado ao executar diagnóstico de latência.",
        )


@app.get(
    "/api/clusters/{cluster_id}/recs",
    tags=["recommendations"],
    summary="Lista recomendações SDRS do cluster",
    description="Retorna as recomendações pendentes do Storage DRS para um datastore cluster.",
)
async def api_get_cluster_recommendations(request: Request, cluster_id: str) -> list[dict[str, Any]]:
    client = get_vcenter_client(request)

    try:
        return await get_pending_recommendations(client, cluster_id)
    except VCenterClientError as exc:
        raise _map_vcenter_error(exc)
    except Exception:
        logger.exception("Erro inesperado ao obter recomendações do cluster %s", cluster_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro inesperado ao obter recomendações do datastore cluster.",
        )


@app.get(
    "/api/clusters/{cluster_id}/candidates",
    tags=["recommendations"],
    summary="Sugestões heurísticas de migração (read-only)",
    description=(
        "Gera candidatos de movimentação de VM com heurística de balanceamento "
        "por uso de datastore. Não aplica nenhuma ação no vCenter."
    ),
)
async def api_get_cluster_candidates(
    request: Request,
    cluster_id: str,
    limit: int = Query(default=20, ge=1, le=50),
) -> dict[str, Any]:
    client = get_vcenter_client(request)

    try:
        return await get_move_candidates(client, cluster_id, limit=limit)
    except VCenterClientError as exc:
        raise _map_vcenter_error(exc)
    except Exception:
        logger.exception("Erro inesperado ao obter candidatos de migração do cluster %s", cluster_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro inesperado ao obter candidatos de migração.",
        )


@app.get(
    "/api/clusters/{cluster_id}/candidates/simulate",
    tags=["recommendations"],
    summary="Simulação de plano de migração (what-if)",
    description=(
        "Simula a aplicação de até N candidatos heurísticos sem executar migração real. "
        "Retorna impacto esperado no balanceamento de espaço do cluster."
    ),
)
async def api_simulate_cluster_candidates(
    request: Request,
    cluster_id: str,
    max_moves: int = Query(default=3, ge=1, le=10),
) -> dict[str, Any]:
    client = get_vcenter_client(request)

    try:
        return await get_simulated_move_plan(client, cluster_id, max_moves=max_moves)
    except VCenterClientError as exc:
        raise _map_vcenter_error(exc)
    except Exception:
        logger.exception("Erro inesperado ao simular plano de migração do cluster %s", cluster_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro inesperado ao simular plano de migração.",
        )


@app.get(
    "/api/clusters/{cluster_id}/datastores/{datastore_id}/vms",
    tags=["datastores"],
    summary="Lista VMs do datastore",
    description="Retorna as VMs visíveis dentro de um datastore do cluster.",
)
async def api_list_datastore_vms(request: Request, cluster_id: str, datastore_id: str) -> dict[str, Any]:
    client = get_vcenter_client(request)
    try:
        payload = await list_datastore_vms(client, cluster_id, datastore_id)
        reason = str(payload.get("reason") or "")
        if reason == "cluster_not_found":
            raise HTTPException(status_code=404, detail="Datastore cluster não encontrado.")
        if reason == "datastore_not_found":
            raise HTTPException(status_code=404, detail="Datastore não encontrado no cluster.")
        return payload
    except HTTPException:
        raise
    except VCenterClientError as exc:
        raise _map_vcenter_error(exc)
    except Exception:
        logger.exception(
            "Erro inesperado ao listar VMs do datastore datastore_id=%s cluster_id=%s",
            datastore_id,
            cluster_id,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro inesperado ao listar VMs do datastore.",
        )


@app.post(
    "/api/clusters/{cluster_id}/vms/{vm_id}/move",
    tags=["datastores"],
    summary="Move VM para outro datastore",
    description="Dispara Storage vMotion manual para mover uma VM entre datastores do cluster.",
)
async def api_move_vm(
    request: Request,
    cluster_id: str,
    vm_id: str,
    payload: VmMovePayload,
) -> dict[str, Any]:
    _require_admin_key_if_configured(request)

    if not ALLOW_VM_STORAGE_MOVE:
        _record_operation_event(
            request,
            action="vm_move_request",
            status_text="blocked",
            details={"cluster_id": cluster_id, "vm_id": vm_id, "reason": "move_disabled_by_policy"},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Move de VM entre datastores está desabilitado por política de segurança.",
        )

    if _is_read_only_mode(request):
        _record_operation_event(
            request,
            action="vm_move_request",
            status_text="blocked",
            details={"cluster_id": cluster_id, "vm_id": vm_id, "reason": "read_only_mode"},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Sistema em modo read-only durante a fase de testes.",
        )

    confirm_header = (request.headers.get("x-confirm-storage-move") or "").strip().lower()
    if confirm_header not in {"yes", "true", "1"}:
        _record_operation_event(
            request,
            action="vm_move_request",
            status_text="blocked",
            details={"cluster_id": cluster_id, "vm_id": vm_id, "reason": "missing_confirmation_header"},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirmação explícita ausente. Envie o cabeçalho X-Confirm-Storage-Move: yes.",
        )

    client = get_vcenter_client(request)
    try:
        response = await move_vm_to_datastore(
            client=client,
            cluster_id=cluster_id,
            vm_id=vm_id,
            target_datastore_id=payload.target_datastore_id,
            source_datastore_id=payload.source_datastore_id,
        )
        _record_operation_event(
            request,
            action="vm_move_request",
            status_text="queued",
            details={
                "cluster_id": cluster_id,
                "vm_id": vm_id,
                "source_datastore_id": payload.source_datastore_id,
                "target_datastore_id": payload.target_datastore_id,
                "task_id": response.get("task_id"),
            },
        )
        return response
    except SDRSOperationError as exc:
        message = str(exc)
        _record_operation_event(
            request,
            action="vm_move_request",
            status_text="error",
            details={
                "cluster_id": cluster_id,
                "vm_id": vm_id,
                "source_datastore_id": payload.source_datastore_id,
                "target_datastore_id": payload.target_datastore_id,
                "error": message,
            },
        )
        lowered = message.lower()
        if "não encontrado" in lowered:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=message)
        if "limite de migrações simultâneas" in lowered or "regras de segurança" in lowered:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=message)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=message)
    except VCenterClientError as exc:
        _record_operation_event(
            request,
            action="vm_move_request",
            status_text="error",
            details={
                "cluster_id": cluster_id,
                "vm_id": vm_id,
                "source_datastore_id": payload.source_datastore_id,
                "target_datastore_id": payload.target_datastore_id,
                "error": str(exc),
            },
        )
        raise _map_vcenter_error(exc)
    except Exception:
        logger.exception(
            "Erro inesperado ao mover VM vm_id=%s cluster_id=%s",
            vm_id,
            cluster_id,
        )
        _record_operation_event(
            request,
            action="vm_move_request",
            status_text="error",
            details={
                "cluster_id": cluster_id,
                "vm_id": vm_id,
                "source_datastore_id": payload.source_datastore_id,
                "target_datastore_id": payload.target_datastore_id,
                "error": "unexpected_error",
            },
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro inesperado ao solicitar migração da VM.",
        )


@app.get(
    "/api/clusters/{cluster_id}/vms/{vm_id}/move/options",
    tags=["datastores"],
    summary="Opções de destino para mover VM",
    description="Retorna destinos compatíveis e projeção de espaço para uma VM no cluster.",
)
async def api_move_vm_options(
    request: Request,
    cluster_id: str,
    vm_id: str,
    source_datastore_id: str | None = None,
) -> dict[str, Any]:
    client = get_vcenter_client(request)
    try:
        payload = await get_move_options_for_vm(
            client=client,
            cluster_id=cluster_id,
            vm_id=vm_id,
            source_datastore_id=source_datastore_id,
        )
        reason = str(payload.get("reason") or "")
        if reason == "cluster_not_found":
            raise HTTPException(status_code=404, detail="Datastore cluster não encontrado.")
        if reason == "source_datastore_not_found":
            raise HTTPException(status_code=404, detail="Datastore de origem não encontrado no cluster.")
        if reason == "vm_not_found":
            raise HTTPException(status_code=404, detail="VM não encontrada no cluster/datastore informado.")
        if reason == "vm_size_unavailable":
            raise HTTPException(status_code=400, detail="Não foi possível estimar o tamanho da VM.")
        return payload
    except HTTPException:
        raise
    except VCenterClientError as exc:
        raise _map_vcenter_error(exc)
    except Exception:
        logger.exception(
            "Erro inesperado ao obter opções de move vm_id=%s cluster_id=%s",
            vm_id,
            cluster_id,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro inesperado ao obter opções de migração da VM.",
        )


@app.get(
    "/api/tasks/{task_id}",
    tags=["tasks"],
    summary="Status de task vCenter",
    description="Consulta o status de uma task de migração no vCenter para acompanhamento em tempo real.",
)
async def api_get_task_status(request: Request, task_id: str) -> dict[str, Any]:
    client = get_vcenter_client(request)
    try:
        payload = await get_task_status(client, task_id)
        if not payload.get("found", False):
            _record_operation_event(
                request,
                action="task_status_query",
                status_text="not_found",
                details={"task_id": task_id},
            )
            raise HTTPException(status_code=404, detail="Task não encontrada.")
        _record_operation_event(
            request,
            action="task_status_query",
            status_text="ok",
            details={"task_id": task_id, "state": payload.get("state"), "found": True},
        )
        return payload
    except HTTPException:
        raise
    except VCenterClientError as exc:
        _record_operation_event(
            request,
            action="task_status_query",
            status_text="error",
            details={"task_id": task_id, "error": str(exc)},
        )
        raise _map_vcenter_error(exc)
    except Exception:
        logger.exception("Erro inesperado ao consultar status da task %s", task_id)
        _record_operation_event(
            request,
            action="task_status_query",
            status_text="error",
            details={"task_id": task_id, "error": "unexpected_error"},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro inesperado ao consultar status da task.",
        )


async def _require_cluster_exists(client: VCenterClient, cluster_id: str) -> dict[str, Any]:
    summaries = await list_clusters(client)
    summary = next((item for item in summaries if str(item.get("id")) == cluster_id), None)
    if summary is None:
        raise HTTPException(status_code=404, detail="Datastore cluster não encontrado.")
    return summary


def _empty_cluster_detail_payload(cluster_id: str, cluster_name: str, datastore_count: int) -> ClusterDetailResponse:
    return ClusterDetailResponse(
        config=ClusterConfig(
            cluster_id=cluster_id,
            name=cluster_name,
            sdrs_enabled=False,
            automation_level="manual",
            space_threshold_percent=95.0,
            sdrs_latency_threshold_ms=None,
            sioc_congestion_threshold_ms=None,
            io_metric_enabled=False,
            capabilities=ClusterCapability(
                io_load_balancing_supported=False,
                maintenance_mode_supported=False,
                rule_inspection_supported=False,
            ),
        ),
        derived=ClusterDerivedDetail(
            total_capacity_gb=0.0,
            total_free_gb=0.0,
            avg_used_percent=0.0,
            max_used_percent=0.0,
            min_used_percent=0.0,
            space_imbalance_percent=0.0,
            space_imbalance_index=0.0,
            cluster_growth_rate_gb_per_day=None,
            cluster_days_to_full=None,
            avg_p90_latency_ms=None,
            worst_p90_latency_ms=None,
            latency_overload_ratio=None,
            performance_health="healthy",
            backend_overloaded_flag=False,
        ),
        suitability=ClusterSuitability(
            score=100,
            protocol_consistent=True,
            media_type_consistent=True,
            performance_class_consistent=True,
            full_host_connectivity=True,
            host_visibility_ratio=1.0,
            mixed_reason=[],
            datastore_count=max(0, datastore_count),
            vmdk_count=None,
            max_datastores=256,
            max_vmdks=9000,
            near_config_maximums=False,
            badges=[],
            warnings=[],
        ),
    )


def _empty_cluster_trends_payload() -> ClusterTrendsResponse:
    return ClusterTrendsResponse(
        window="24h",
        resolution="1h",
        series=ClusterTrendsSeries(
            avg_used_percent=[],
            space_imbalance_percent=[],
            worst_p90_latency_ms=[],
            latency_overload_ratio=[],
            recommendations_generated=[],
            recommendations_applied=[],
        ),
    )


@app.get(
    "/api/analytics/dashboard/snapshot",
    tags=["analytics"],
    response_model=DashboardSnapshot,
    summary="Snapshot global analítico",
)
async def api_dashboard_snapshot(request: Request) -> DashboardSnapshot:
    _ = request
    return DashboardSnapshot(
        collected_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        **{
            "global": GlobalSnapshot(
                cluster_count=0,
                datastore_count=0,
                total_capacity_gb=0.0,
                total_free_gb=0.0,
                clusters_with_risk=0,
                clusters_with_partial_connectivity=0,
                pending_recommendations=0,
                applied_recommendations_7d=0,
                dismissed_recommendations_7d=0,
            )
        },
        clusters=[],
        alerts=[],
    )


@app.get(
    "/api/analytics/clusters/overview",
    tags=["analytics"],
    response_model=ClusterOverviewResponse,
    summary="Resumo analítico de clusters",
)
async def api_cluster_overview(request: Request) -> ClusterOverviewResponse:
    _ = request
    return ClusterOverviewResponse(items=[])


@app.get(
    "/api/analytics/clusters/insights",
    tags=["analytics"],
    response_model=ClusterInsightsResponse,
    summary="Top insights por cluster",
)
async def api_cluster_insights(request: Request) -> ClusterInsightsResponse:
    _ = request
    return ClusterInsightsResponse(items=[])


@app.get(
    "/api/analytics/clusters/{cluster_id}/detail",
    tags=["analytics"],
    response_model=ClusterDetailResponse,
    summary="Detalhe analítico tipado de cluster",
)
async def api_cluster_typed_detail(request: Request, cluster_id: str) -> ClusterDetailResponse:
    client = get_vcenter_client(request)
    try:
        summary = await _require_cluster_exists(client, cluster_id)
        return _empty_cluster_detail_payload(
            cluster_id=cluster_id,
            cluster_name=str(summary.get("name") or "Unknown"),
            datastore_count=int(summary.get("datastore_count") or 0),
        )
    except HTTPException:
        raise
    except VCenterClientError as exc:
        raise _map_vcenter_error(exc)
    except Exception:
        logger.exception("Erro inesperado no detalhe analítico do cluster %s", cluster_id)
        raise HTTPException(status_code=500, detail="Erro no detalhe analítico do cluster.")


@app.get(
    "/api/analytics/clusters/{cluster_id}/datastores/metrics",
    tags=["analytics"],
    response_model=DatastoreMetricsResponse,
    summary="Métricas atuais dos datastores do cluster",
)
async def api_cluster_datastore_metrics(request: Request, cluster_id: str) -> DatastoreMetricsResponse:
    client = get_vcenter_client(request)
    try:
        await _require_cluster_exists(client, cluster_id)
        return DatastoreMetricsResponse(items=[])
    except HTTPException:
        raise
    except VCenterClientError as exc:
        raise _map_vcenter_error(exc)
    except Exception:
        logger.exception("Erro inesperado ao montar métricas de datastores do cluster %s", cluster_id)
        raise HTTPException(status_code=500, detail="Erro ao montar métricas de datastores.")


@app.get(
    "/api/analytics/clusters/{cluster_id}/trends",
    tags=["analytics"],
    response_model=ClusterTrendsResponse,
    summary="Série temporal resumida do cluster",
)
async def api_cluster_trends(request: Request, cluster_id: str) -> ClusterTrendsResponse:
    client = get_vcenter_client(request)
    try:
        await _require_cluster_exists(client, cluster_id)
        return _empty_cluster_trends_payload()
    except HTTPException:
        raise
    except VCenterClientError as exc:
        raise _map_vcenter_error(exc)
    except Exception:
        logger.exception("Erro inesperado ao montar trends do cluster %s", cluster_id)
        raise HTTPException(status_code=500, detail="Erro ao montar trends do cluster.")


@app.get(
    "/api/analytics/clusters/{cluster_id}/recommendations/pending",
    tags=["analytics"],
    response_model=PendingRecommendationsResponse,
    summary="Recomendações pendentes tipadas",
)
async def api_cluster_pending_recommendations(
    request: Request, cluster_id: str
) -> PendingRecommendationsResponse:
    client = get_vcenter_client(request)
    try:
        await _require_cluster_exists(client, cluster_id)
        return _build_pending_recommendations(cluster_id, [])
    except HTTPException:
        raise
    except VCenterClientError as exc:
        raise _map_vcenter_error(exc)
    except Exception:
        logger.exception("Erro inesperado ao montar pending recommendations do cluster %s", cluster_id)
        raise HTTPException(status_code=500, detail="Erro ao montar recomendações pendentes.")


@app.get(
    "/api/analytics/clusters/{cluster_id}/recommendations/stats",
    tags=["analytics"],
    response_model=RecommendationStatsResponse,
    summary="Estatísticas de recomendações do cluster",
)
async def api_cluster_recommendation_stats(
    request: Request, cluster_id: str
) -> RecommendationStatsResponse:
    client = get_vcenter_client(request)
    try:
        await _require_cluster_exists(client, cluster_id)
        pending_payload = _build_pending_recommendations(cluster_id, [])
        return _build_recommendation_stats(pending_payload)
    except HTTPException:
        raise
    except VCenterClientError as exc:
        raise _map_vcenter_error(exc)
    except Exception:
        logger.exception("Erro inesperado ao montar recommendation stats do cluster %s", cluster_id)
        raise HTTPException(status_code=500, detail="Erro ao montar estatísticas de recomendações.")


@app.get(
    "/api/analytics/clusters/{cluster_id}/risk",
    tags=["analytics"],
    response_model=ClusterRiskResponse,
    summary="Visão de risco operacional do cluster",
)
async def api_cluster_risk(request: Request, cluster_id: str) -> ClusterRiskResponse:
    client = get_vcenter_client(request)
    try:
        await _require_cluster_exists(client, cluster_id)
        return ClusterRiskResponse(near_full=[], maintenance=[], constraints=[])
    except HTTPException:
        raise
    except VCenterClientError as exc:
        raise _map_vcenter_error(exc)
    except Exception:
        logger.exception("Erro inesperado ao montar risco do cluster %s", cluster_id)
        raise HTTPException(status_code=500, detail="Erro ao montar visão de risco do cluster.")


@app.post(
    "/api/clusters/{cluster_id}/recs/{key}/apply",
    tags=["recommendations"],
    summary="Aplicar recomendação SDRS",
    description="Stub seguro para futura aplicação manual de recomendações do Storage DRS.",
)
async def api_apply_recommendation(request: Request, cluster_id: str, key: str) -> dict[str, Any]:
    _record_operation_event(
        request,
        action="recommendation_apply",
        status_text="blocked",
        details={"cluster_id": cluster_id, "key": key, "reason": "operation_blocked_by_policy"},
    )
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Operação bloqueada por política de segurança. Esta aplicação não aplica/dispensa recomendações.",
    )


@app.post(
    "/api/clusters/{cluster_id}/recs/{key}/dismiss",
    tags=["recommendations"],
    summary="Dispensar recomendação SDRS",
    description="Stub seguro para futura dispensa manual de recomendações do Storage DRS.",
)
async def api_dismiss_recommendation(request: Request, cluster_id: str, key: str) -> dict[str, Any]:
    _record_operation_event(
        request,
        action="recommendation_dismiss",
        status_text="blocked",
        details={"cluster_id": cluster_id, "key": key, "reason": "operation_blocked_by_policy"},
    )
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Operação bloqueada por política de segurança. Esta aplicação não aplica/dispensa recomendações.",
    )
