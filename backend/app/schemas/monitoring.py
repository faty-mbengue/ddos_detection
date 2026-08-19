from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

# ── Paquets ───────────────────────────────────────────────────────────────────


class PacketRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    packet_no: int
    time: float
    src_ip: str
    dst_ip: str
    protocol: str
    length: int
    info: str


# ── Flux ──────────────────────────────────────────────────────────────────────


class FlowSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    flow_duration: float
    flow_byts_s: float
    flow_pkts_s: float
    tot_fwd_pkts: int
    tot_bwd_pkts: int
    totlen_fwd_pkts: int
    totlen_bwd_pkts: int


# ── Predictions ───────────────────────────────────────────────────────────────


class PredictionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    flow_id: int | None
    prediction: str
    confidence: float
    is_attack: bool
    prediction_timestamp: datetime


class PredictionDetail(PredictionRead):
    flow: FlowSummary | None = None


class PredictRequest(BaseModel):
    """Prediction a la demande sur un vecteur de caracteristiques."""

    features: list[float] = Field(
        min_length=1,
        description=(
            "Les 31 caracteristiques dans l'ordre de /api/model/features. "
            "Valeurs BRUTES CICFlowMeter par defaut ; le scaler du modele les met "
            "a l'echelle."
        ),
    )
    scaled: bool = Field(
        default=False,
        description=(
            "Mettre a true si le vecteur est deja normalise dans [0, 1] "
            "(par exemple une ligne recopiee du notebook) : le scaler est alors ignore."
        ),
    )
    persist: bool = Field(default=False, description="Enregistrer le resultat en base")


class PredictBatchRequest(BaseModel):
    """Prediction sur un lot de vecteurs, memes conventions que PredictRequest."""

    rows: list[list[float]] = Field(min_length=1, max_length=5000)
    scaled: bool = Field(default=False)


class PredictResponse(BaseModel):
    prediction: str
    class_index: int
    confidence: float
    is_attack: bool
    probabilities: dict[str, float]


# ── Attaques ──────────────────────────────────────────────────────────────────


class AttackRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    attack_type: str
    source_ip: str
    destination_ip: str
    flows_count: int
    total_bytes: int
    total_packets: int
    duration: float
    avg_confidence: float
    severity: str
    status: str


# ── Statistiques et tableaux de bord ──────────────────────────────────────────


class StatisticRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    total_flows: int
    total_attacks: int
    benign_flows: int
    packets_per_second: float
    bytes_per_second: float
    active_attacks: int


class ClassCount(BaseModel):
    name: str
    count: int
    is_attack: bool


class TimeBucket(BaseModel):
    bucket: datetime
    attacks: int
    benign: int


class ClassConfidence(BaseModel):
    name: str
    avg_confidence: float
    count: int


class Overview(BaseModel):
    """Indicateurs de tete affiches sur le tableau de bord."""

    total_flows: int
    total_attacks: int
    benign_flows: int
    active_attacks: int
    attack_ratio: float
    packets_per_second: float
    bytes_per_second: float
    distinct_attack_types: int
    top_source_ip: str | None
    last_attack_at: datetime | None
    system_status: str  # NORMAL / ATTACK
    updated_at: datetime


class DashboardResponse(BaseModel):
    overview: Overview
    class_distribution: list[ClassCount]
    attacks_over_time: list[TimeBucket]
    confidence_by_class: list[ClassConfidence]
    recent_attacks: list[AttackRead]
    throughput_history: list[StatisticRead]


# ── Administration ────────────────────────────────────────────────────────────


class BlockedIPRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ip_address: str
    reason: str
    blocked_by: str
    is_automatic: bool
    created_at: datetime


class BlockedIPCreate(BaseModel):
    ip_address: str = Field(min_length=3, max_length=45)
    reason: str = Field(default="Blocage manuel", max_length=200)


class SystemSettings(BaseModel):
    """Configuration ajustable depuis l'administration."""

    capture_backend: str | None = Field(
        default=None,
        description="simulator | external | tshark",
    )
    capture_interface: str | None = None
    analysis_interval: int | None = Field(default=None, ge=5, le=300)
    confidence_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    flow_threshold: int | None = Field(default=None, ge=1, le=1000)
    auto_block: bool | None = None
    email_alerts: bool | None = None
    alert_recipients: str | None = None


class SystemStatus(BaseModel):
    pipeline_running: bool
    cycles: int
    last_cycle_at: datetime | None
    interval_seconds: int
    last_error: str | None
    capture: dict
    model: dict
    ws_clients: int


class PaginatedResponse(BaseModel):
    total: int
    limit: int
    offset: int
