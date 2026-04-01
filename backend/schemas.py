from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ClusterCapability(BaseModel):
    io_load_balancing_supported: bool
    maintenance_mode_supported: bool
    rule_inspection_supported: bool


class ClusterConfig(BaseModel):
    cluster_id: str
    name: str
    sdrs_enabled: bool
    automation_level: Literal["manual", "automated", "disabled"]
    space_threshold_percent: float
    sdrs_latency_threshold_ms: float | None
    sioc_congestion_threshold_ms: float | None
    io_metric_enabled: bool | None
    capabilities: ClusterCapability


class ClusterSuitability(BaseModel):
    score: int
    protocol_consistent: bool
    media_type_consistent: bool
    performance_class_consistent: bool | None
    full_host_connectivity: bool
    host_visibility_ratio: float
    mixed_reason: list[str]
    datastore_count: int
    vmdk_count: int | None
    max_datastores: int
    max_vmdks: int
    near_config_maximums: bool
    badges: list[str]
    warnings: list[str]


class DatastoreCurrentMetrics(BaseModel):
    datastore_id: str
    name: str
    cluster_id: str
    total_capacity_gb: float
    free_space_gb: float
    used_percent: float
    above_space_threshold: bool
    critical_used_percent: bool
    growth_rate_gb_per_day: float | None
    growth_rate_percent_per_day: float | None
    days_to_full: float | None
    avg_read_latency_ms: float | None
    avg_write_latency_ms: float | None
    p90_latency_ms: float | None
    iops_read: float | None
    iops_write: float | None
    throughput_read_mb_s: float | None
    throughput_write_mb_s: float | None
    near_latency_threshold: bool
    above_latency_threshold: bool
    maintenance_requested: bool
    evacuation_progress_percent: float | None


class ClusterDerivedMetrics(BaseModel):
    cluster_id: str
    total_capacity_gb: float
    total_free_gb: float
    avg_used_percent: float
    max_used_percent: float
    min_used_percent: float
    space_imbalance_percent: float
    space_imbalance_index: float
    cluster_growth_rate_gb_per_day: float | None
    cluster_days_to_full: float | None
    avg_p90_latency_ms: float | None
    worst_p90_latency_ms: float | None
    latency_overload_ratio: float | None
    performance_health: Literal["healthy", "warning", "critical"]
    backend_overloaded_flag: bool


class RecommendationEvent(BaseModel):
    recommendation_key: str
    cluster_id: str
    reason_type: Literal[
        "space_balance",
        "latency_balance",
        "maintenance_evacuation",
        "rule_correction",
        "other",
    ]
    status: Literal["pending", "applied", "dismissed", "failed", "expired"]
    vm_name: str | None
    source_datastore_id: str | None
    target_datastore_id: str | None
    size_gb: float | None
    created_at: str
    acted_at: str | None
    actor: str | None


class RecommendationImpact(BaseModel):
    recommendation_key: str
    before_space_source_percent: float | None
    before_space_target_percent: float | None
    after_space_source_percent: float | None
    after_space_target_percent: float | None
    before_latency_source_ms: float | None
    before_latency_target_ms: float | None
    after_latency_source_ms: float | None
    after_latency_target_ms: float | None
    space_imbalance_delta: float | None
    latency_delta_ms: float | None
    helped_space: bool | None
    helped_latency: bool | None


class GlobalSnapshot(BaseModel):
    cluster_count: int
    datastore_count: int
    total_capacity_gb: float
    total_free_gb: float
    clusters_with_risk: int
    clusters_with_partial_connectivity: int
    pending_recommendations: int
    applied_recommendations_7d: int
    dismissed_recommendations_7d: int


class ClusterSnapshot(BaseModel):
    cluster_id: str
    name: str
    sdrs_enabled: bool
    automation_level: Literal["manual", "automated", "disabled"]
    total_free_gb: float
    avg_used_percent: float
    space_imbalance_percent: float
    space_imbalance_index: float
    worst_p90_latency_ms: float | None
    latency_overload_ratio: float | None
    performance_health: Literal["healthy", "warning", "critical"]
    suitability_score: int
    pending_recommendations: int
    risk_level: Literal["healthy", "warning", "critical"]


class SnapshotAlert(BaseModel):
    type: str
    severity: Literal["warning", "critical"]
    cluster_id: str
    datastore_id: str
    title: str
    deep_link: str


class DashboardSnapshot(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    collected_at: str
    global_: GlobalSnapshot = Field(alias="global")
    clusters: list[ClusterSnapshot]
    alerts: list[SnapshotAlert]


class ClusterOverviewItem(BaseModel):
    cluster_id: str
    name: str
    sdrs_enabled: bool
    automation_level: Literal["manual", "automated", "disabled"]
    space_threshold_percent: float
    latency_threshold_ms: float | None
    total_capacity_gb: float
    total_free_gb: float
    avg_used_percent: float
    space_imbalance_percent: float
    worst_p90_latency_ms: float | None
    datastores_near_threshold: int
    pending_recommendations: int
    suitability_score: int
    badges: list[str]


class ClusterOverviewResponse(BaseModel):
    items: list[ClusterOverviewItem]


class ClusterDerivedDetail(BaseModel):
    total_capacity_gb: float
    total_free_gb: float
    avg_used_percent: float
    max_used_percent: float
    min_used_percent: float
    space_imbalance_percent: float
    space_imbalance_index: float
    cluster_growth_rate_gb_per_day: float | None
    cluster_days_to_full: float | None
    avg_p90_latency_ms: float | None
    worst_p90_latency_ms: float | None
    latency_overload_ratio: float | None
    performance_health: Literal["healthy", "warning", "critical"]
    backend_overloaded_flag: bool


class ClusterDetailResponse(BaseModel):
    config: ClusterConfig
    derived: ClusterDerivedDetail
    suitability: ClusterSuitability


class DatastoreMetricsItem(BaseModel):
    datastore_id: str
    name: str
    total_capacity_gb: float
    free_space_gb: float
    used_percent: float
    above_space_threshold: bool
    critical_used_percent: bool
    growth_rate_gb_per_day: float | None
    growth_rate_percent_per_day: float | None
    days_to_full: float | None
    avg_read_latency_ms: float | None
    avg_write_latency_ms: float | None
    p90_latency_ms: float | None
    iops_read: float | None
    iops_write: float | None
    throughput_read_mb_s: float | None
    throughput_write_mb_s: float | None
    near_latency_threshold: bool
    above_latency_threshold: bool
    maintenance_requested: bool
    evacuation_progress_percent: float | None


class DatastoreMetricsResponse(BaseModel):
    items: list[DatastoreMetricsItem]


class ClusterTrendsSeries(BaseModel):
    avg_used_percent: list[tuple[str, float]]
    space_imbalance_percent: list[tuple[str, float]]
    worst_p90_latency_ms: list[tuple[str, float]]
    latency_overload_ratio: list[tuple[str, float]]
    recommendations_generated: list[tuple[str, int]]
    recommendations_applied: list[tuple[str, int]]


class ClusterTrendsResponse(BaseModel):
    window: str
    resolution: str
    series: ClusterTrendsSeries


class PendingRecommendationItem(BaseModel):
    recommendation_key: str
    reason_type: Literal[
        "space_balance",
        "latency_balance",
        "maintenance_evacuation",
        "rule_correction",
        "other",
    ]
    status: Literal["pending", "applied", "dismissed", "failed", "expired"]
    vm_name: str | None
    source_datastore_id: str | None
    target_datastore_id: str | None
    size_gb: float | None
    created_at: str


class PendingRecommendationsSummary(BaseModel):
    pending_count: int
    space_balance_count: int
    latency_balance_count: int
    maintenance_evacuation_count: int


class PendingRecommendationsResponse(BaseModel):
    pending: list[PendingRecommendationItem]
    summary: PendingRecommendationsSummary


class RecommendationWindowCounts(BaseModel):
    generated: int
    applied: int
    dismissed: int
    failed: int
    expired: int


class RecommendationReasonBreakdown(BaseModel):
    generated: int
    applied: int
    dismissed: int


class RecommendationsByReason(BaseModel):
    space_balance: RecommendationReasonBreakdown
    latency_balance: RecommendationReasonBreakdown
    maintenance_evacuation: RecommendationReasonBreakdown


class RecommendationStatsResponse(BaseModel):
    window: str
    counts: RecommendationWindowCounts
    by_reason: RecommendationsByReason
    acceptance_rate: float
    avg_space_imbalance_delta: float | None
    avg_latency_delta_ms: float | None
    patterns: list[str]


class NearFullDatastoreItem(BaseModel):
    datastore_id: str
    name: str
    used_percent: float
    days_to_full: float | None
    sdrs_recommendations_pending: int


class MaintenanceDatastoreItem(BaseModel):
    datastore_id: str
    name: str
    maintenance_requested: bool
    migrated_vmdks: int
    total_vmdks: int
    progress_percent: float


class ConstraintImpactItem(BaseModel):
    type: str
    name: str
    blocked_recommendations: int


class ClusterRiskResponse(BaseModel):
    near_full: list[NearFullDatastoreItem]
    maintenance: list[MaintenanceDatastoreItem]
    constraints: list[ConstraintImpactItem]


class ClusterInsightItem(BaseModel):
    cluster_id: str
    name: str
    score: int
    space_imbalance_index: float
    latency_overload_ratio: float | None
    migrations_per_day: float | None
    automation_level: Literal["manual", "automated", "disabled"]
    diagnosis: list[str]


class ClusterInsightsResponse(BaseModel):
    items: list[ClusterInsightItem]
