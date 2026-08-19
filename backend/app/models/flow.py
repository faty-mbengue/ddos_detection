"""Table flows - flux reseau bruts extraits par CICFlowMeter.

Le schema reprend la nomenclature de sortie de CICFlowMeter (cf. Description systeme, 6.1).
"""

from datetime import UTC, datetime

from sqlalchemy import BigInteger, DateTime, Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class Flow(Base):
    __tablename__ = "flows"

    id: Mapped[int] = mapped_column(primary_key=True)

    # ── Identification du flux ────────────────────────────────────────────────
    src_ip: Mapped[str] = mapped_column(String(45), index=True)
    dst_ip: Mapped[str] = mapped_column(String(45), index=True)
    src_port: Mapped[int] = mapped_column(Integer, default=0)
    dst_port: Mapped[int] = mapped_column(Integer, default=0)
    protocol: Mapped[int] = mapped_column(Integer, default=0)  # 6=TCP, 17=UDP
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True
    )

    # Provenance de la donnee : "simulator", "external" ou "tshark". Permet de ne
    # jamais melanger du trafic synthetique avec du trafic reel dans les analyses.
    source: Mapped[str] = mapped_column(String(12), default="simulator", index=True)

    # ── Debits et duree ───────────────────────────────────────────────────────
    flow_duration: Mapped[float] = mapped_column(Float, default=0.0)
    flow_byts_s: Mapped[float] = mapped_column(Float, default=0.0)
    flow_pkts_s: Mapped[float] = mapped_column(Float, default=0.0)
    fwd_pkts_s: Mapped[float] = mapped_column(Float, default=0.0)
    bwd_pkts_s: Mapped[float] = mapped_column(Float, default=0.0)

    # ── Volumetrie ────────────────────────────────────────────────────────────
    tot_fwd_pkts: Mapped[int] = mapped_column(Integer, default=0)
    tot_bwd_pkts: Mapped[int] = mapped_column(Integer, default=0)
    totlen_fwd_pkts: Mapped[int] = mapped_column(BigInteger, default=0)
    totlen_bwd_pkts: Mapped[int] = mapped_column(BigInteger, default=0)

    # ── Taille des paquets ────────────────────────────────────────────────────
    fwd_pkt_len_max: Mapped[int] = mapped_column(Integer, default=0)
    fwd_pkt_len_min: Mapped[int] = mapped_column(Integer, default=0)
    fwd_pkt_len_mean: Mapped[float] = mapped_column(Float, default=0.0)
    fwd_pkt_len_std: Mapped[float] = mapped_column(Float, default=0.0)
    bwd_pkt_len_max: Mapped[int] = mapped_column(Integer, default=0)
    bwd_pkt_len_min: Mapped[int] = mapped_column(Integer, default=0)
    bwd_pkt_len_mean: Mapped[float] = mapped_column(Float, default=0.0)
    bwd_pkt_len_std: Mapped[float] = mapped_column(Float, default=0.0)
    pkt_len_max: Mapped[int] = mapped_column(Integer, default=0)
    pkt_len_min: Mapped[int] = mapped_column(Integer, default=0)
    pkt_len_mean: Mapped[float] = mapped_column(Float, default=0.0)
    pkt_len_std: Mapped[float] = mapped_column(Float, default=0.0)
    pkt_len_var: Mapped[float] = mapped_column(Float, default=0.0)
    pkt_size_avg: Mapped[float] = mapped_column(Float, default=0.0)

    # ── En-tetes et segments ──────────────────────────────────────────────────
    fwd_header_len: Mapped[int] = mapped_column(Integer, default=0)
    bwd_header_len: Mapped[int] = mapped_column(Integer, default=0)
    fwd_seg_size_min: Mapped[int] = mapped_column(Integer, default=0)
    fwd_seg_size_avg: Mapped[float] = mapped_column(Float, default=0.0)
    bwd_seg_size_avg: Mapped[float] = mapped_column(Float, default=0.0)
    fwd_act_data_pkts: Mapped[int] = mapped_column(Integer, default=0)

    # ── Inter-Arrival Time ────────────────────────────────────────────────────
    flow_iat_mean: Mapped[float] = mapped_column(Float, default=0.0)
    flow_iat_max: Mapped[float] = mapped_column(Float, default=0.0)
    flow_iat_min: Mapped[float] = mapped_column(Float, default=0.0)
    flow_iat_std: Mapped[float] = mapped_column(Float, default=0.0)
    fwd_iat_tot: Mapped[float] = mapped_column(Float, default=0.0)
    fwd_iat_max: Mapped[float] = mapped_column(Float, default=0.0)
    fwd_iat_min: Mapped[float] = mapped_column(Float, default=0.0)
    fwd_iat_mean: Mapped[float] = mapped_column(Float, default=0.0)
    fwd_iat_std: Mapped[float] = mapped_column(Float, default=0.0)
    bwd_iat_tot: Mapped[float] = mapped_column(Float, default=0.0)
    bwd_iat_max: Mapped[float] = mapped_column(Float, default=0.0)
    bwd_iat_min: Mapped[float] = mapped_column(Float, default=0.0)
    bwd_iat_mean: Mapped[float] = mapped_column(Float, default=0.0)
    bwd_iat_std: Mapped[float] = mapped_column(Float, default=0.0)

    # ── Drapeaux TCP ──────────────────────────────────────────────────────────
    fwd_psh_flags: Mapped[int] = mapped_column(Integer, default=0)
    bwd_psh_flags: Mapped[int] = mapped_column(Integer, default=0)
    fwd_urg_flags: Mapped[int] = mapped_column(Integer, default=0)
    bwd_urg_flags: Mapped[int] = mapped_column(Integer, default=0)
    fin_flag_cnt: Mapped[int] = mapped_column(Integer, default=0)
    syn_flag_cnt: Mapped[int] = mapped_column(Integer, default=0)
    rst_flag_cnt: Mapped[int] = mapped_column(Integer, default=0)
    psh_flag_cnt: Mapped[int] = mapped_column(Integer, default=0)
    ack_flag_cnt: Mapped[int] = mapped_column(Integer, default=0)
    urg_flag_cnt: Mapped[int] = mapped_column(Integer, default=0)
    ece_flag_cnt: Mapped[int] = mapped_column(Integer, default=0)
    cwr_flag_count: Mapped[int] = mapped_column(Integer, default=0)

    # ── Fenetres et ratio ─────────────────────────────────────────────────────
    down_up_ratio: Mapped[float] = mapped_column(Float, default=0.0)
    init_fwd_win_byts: Mapped[int] = mapped_column(Integer, default=0)
    init_bwd_win_byts: Mapped[int] = mapped_column(Integer, default=0)

    # ── Periodes d'activite / inactivite ──────────────────────────────────────
    active_max: Mapped[float] = mapped_column(Float, default=0.0)
    active_min: Mapped[float] = mapped_column(Float, default=0.0)
    active_mean: Mapped[float] = mapped_column(Float, default=0.0)
    active_std: Mapped[float] = mapped_column(Float, default=0.0)
    idle_max: Mapped[float] = mapped_column(Float, default=0.0)
    idle_min: Mapped[float] = mapped_column(Float, default=0.0)
    idle_mean: Mapped[float] = mapped_column(Float, default=0.0)
    idle_std: Mapped[float] = mapped_column(Float, default=0.0)

    # ── Statistiques bulk ─────────────────────────────────────────────────────
    fwd_byts_b_avg: Mapped[float] = mapped_column(Float, default=0.0)
    fwd_pkts_b_avg: Mapped[float] = mapped_column(Float, default=0.0)
    bwd_byts_b_avg: Mapped[float] = mapped_column(Float, default=0.0)
    bwd_pkts_b_avg: Mapped[float] = mapped_column(Float, default=0.0)
    fwd_blk_rate_avg: Mapped[float] = mapped_column(Float, default=0.0)
    bwd_blk_rate_avg: Mapped[float] = mapped_column(Float, default=0.0)

    # ── Sous-flux ─────────────────────────────────────────────────────────────
    subflow_fwd_pkts: Mapped[int] = mapped_column(Integer, default=0)
    subflow_bwd_pkts: Mapped[int] = mapped_column(Integer, default=0)
    subflow_fwd_byts: Mapped[int] = mapped_column(BigInteger, default=0)
    subflow_bwd_byts: Mapped[int] = mapped_column(BigInteger, default=0)

    prediction = relationship(
        "Prediction", back_populates="flow", uselist=False, cascade="all, delete-orphan"
    )
