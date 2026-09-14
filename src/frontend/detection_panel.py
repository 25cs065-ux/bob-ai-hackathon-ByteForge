"""
detection_panel.py — Frontend panel for Module 2: Detection & Scoring.

Usage:
    from frontend.detection_panel import render_detection_panel
    render_detection_panel(incident)

Reads only the Detection & Scoring fields already defined on Incident:
    incident.risk_score
    incident.priority
    incident.is_false_positive
    incident.false_positive_reason
    incident.threat_dna_signature
    incident.similar_past_incidents
    incident.status
    incident.alerts
"""

import streamlit as st

try:
    from detection.risk_scoring import explain_risk_score as _explain_risk_score
    _EXPLAIN_AVAILABLE = True
except Exception:
    _EXPLAIN_AVAILABLE = False
    _explain_risk_score = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Priority / severity colour maps
# ---------------------------------------------------------------------------
_PRIORITY_HEX = {
    "Critical": "#f85149",
    "High":     "#e3b341",
    "Medium":   "#58a6ff",
    "Low":      "#3fb950",
}
_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}
_SEVERITY_HEX = {
    "critical": "#f85149",
    "high":     "#e3b341",
    "medium":   "#58a6ff",
    "low":      "#3fb950",
}


def _pri_hex(priority: str) -> str:
    return _PRIORITY_HEX.get(priority or "", "#8b949e")


# ---------------------------------------------------------------------------
# Section helpers
# ---------------------------------------------------------------------------

def _section_label(text: str) -> None:
    """Render a small uppercase section label."""
    st.markdown(
        f'<div style="font-size:0.68rem;color:#8b949e;text-transform:uppercase;'
        f'letter-spacing:0.12em;margin-bottom:8px;border-bottom:1px solid #1e2a38;'
        f'padding-bottom:5px;">{text}</div>',
        unsafe_allow_html=True,
    )


def _render_risk_assessment(incident) -> None:
    """Risk Score (prominent) + Priority + Status + explainability expander."""
    _section_label("Risk Assessment")

    score  = incident.risk_score
    pri    = incident.priority or "Unknown"
    status = (incident.status or "unknown").upper()

    display_score = round(float(score), 1) if score is not None else None
    pct           = min(max(float(score) / 100.0, 0.0), 1.0) if score is not None else 0.0
    pri_colour    = _pri_hex(pri)

    # Build the filled/empty progress bar as HTML so we can colour it
    bar_filled = int(pct * 20)
    bar_empty  = 20 - bar_filled
    bar_html   = (
        f'<span style="color:{pri_colour};">{"█" * bar_filled}</span>'
        f'<span style="color:#1e2a38;">{"█" * bar_empty}</span>'
    )

    col_score, col_pri, col_status = st.columns(3)

    with col_score:
        if display_score is not None:
            st.markdown(
                f'<div style="background:#0d1117;border:1px solid #1e2a38;border-top:2px solid {pri_colour};'
                f'border-radius:4px;padding:16px 20px;">'
                f'<div style="font-size:0.68rem;color:#8b949e;text-transform:uppercase;letter-spacing:0.1em;">Risk Score</div>'
                f'<div style="font-size:2.2rem;font-weight:800;color:{pri_colour};line-height:1.1;margin-top:2px;">{display_score}</div>'
                f'<div style="font-size:0.72rem;color:#8b949e;margin-top:1px;">/ 100</div>'
                f'<div style="font-family:monospace;font-size:0.85rem;letter-spacing:0.02em;margin-top:8px;">{bar_html}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )
        else:
            st.metric("Risk Score", "N/A")

    with col_pri:
        st.markdown(
            f'<div style="background:#0d1117;border:1px solid #1e2a38;border-top:2px solid {pri_colour};'
            f'border-radius:4px;padding:16px 20px;height:100%;">'
            f'<div style="font-size:0.68rem;color:#8b949e;text-transform:uppercase;letter-spacing:0.1em;">Priority</div>'
            f'<div style="font-size:1.4rem;font-weight:800;color:{pri_colour};margin-top:6px;">{pri}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

    with col_status:
        st.markdown(
            f'<div style="background:#0d1117;border:1px solid #1e2a38;border-top:2px solid #1e2a38;'
            f'border-radius:4px;padding:16px 20px;height:100%;">'
            f'<div style="font-size:0.68rem;color:#8b949e;text-transform:uppercase;letter-spacing:0.1em;">Status</div>'
            f'<div style="font-size:1.4rem;font-weight:800;color:#c9d1d9;margin-top:6px;">{status}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

    # ── "Why this score?" expander ────────────────────────────────────────
    if _EXPLAIN_AVAILABLE and score is not None:
        with st.expander("Why this score?", expanded=False):
            st.markdown(
                '<div style="font-size:0.72rem;color:#6e7681;margin-bottom:10px;">'
                'Score is calculated from observed incident evidence using the '
                'detection scoring rules (severity, suspicious event types, '
                'high-value assets, source diversity, and volume damping).'
                '</div>',
                unsafe_allow_html=True,
            )
            try:
                factors = _explain_risk_score(incident)
                # Separate the final-score line for emphasis
                main_factors = [f for f in factors if not f[0].startswith("Final score")]
                final_factor = next((f for f in factors if f[0].startswith("Final score")), None)

                rows_html = ""
                for label, detail in main_factors:
                    rows_html += (
                        f'<div style="display:flex;gap:0;padding:5px 0;'
                        f'border-bottom:1px solid #1e2a38;">'
                        f'<div style="min-width:210px;font-size:0.72rem;font-weight:600;'
                        f'color:#8b949e;text-transform:uppercase;letter-spacing:0.06em;'
                        f'padding-right:12px;">{label}</div>'
                        f'<div style="font-size:0.78rem;color:#c9d1d9;flex:1;">{detail}</div>'
                        f'</div>'
                    )
                st.markdown(
                    f'<div style="background:#0d1117;border:1px solid #1e2a38;'
                    f'border-radius:3px;padding:8px 12px;">{rows_html}</div>',
                    unsafe_allow_html=True,
                )

                if final_factor:
                    st.markdown(
                        f'<div style="margin-top:8px;background:#0d1117;border:1px solid #1e2a38;'
                        f'border-left:3px solid {pri_colour};border-radius:3px;'
                        f'padding:8px 14px;display:flex;align-items:center;gap:12px;">'
                        f'<div style="font-size:0.68rem;color:#8b949e;text-transform:uppercase;'
                        f'letter-spacing:0.08em;">{final_factor[0]}</div>'
                        f'<div style="font-size:1.4rem;font-weight:800;color:{pri_colour};">'
                        f'{final_factor[1]}</div>'
                        f'</div>',
                        unsafe_allow_html=True,
                    )
            except Exception as exc:
                st.caption(f"Score explanation unavailable: {exc}")


def _render_false_positive(incident) -> None:
    """False positive assessment block."""
    _section_label("False Positive Assessment")

    fp     = incident.is_false_positive
    reason = incident.false_positive_reason

    if fp is True:
        verdict_colour = "#f85149"
        verdict_label  = "YES — False Positive"
        verdict_icon   = "⚠"
    elif fp is False:
        verdict_colour = "#3fb950"
        verdict_label  = "NO — Genuine Threat"
        verdict_icon   = "✓"
    else:
        verdict_colour = "#8b949e"
        verdict_label  = "UNKNOWN"
        verdict_icon   = "?"

    st.markdown(
        f'<div style="background:#0d1117;border:1px solid #1e2a38;border-left:3px solid {verdict_colour};'
        f'border-radius:4px;padding:12px 16px;">'
        f'<span style="color:{verdict_colour};font-weight:700;font-size:0.9rem;">{verdict_icon} {verdict_label}</span>'
        + (f'<div style="color:#8b949e;font-size:0.8rem;margin-top:6px;">{reason}</div>' if reason else '')
        + f'</div>',
        unsafe_allow_html=True,
    )


def _render_threat_dna(incident) -> None:
    """Threat DNA signature block."""
    _section_label("Threat DNA Signature")

    dna = incident.threat_dna_signature
    if dna:
        st.code(dna, language=None)
    else:
        st.markdown(
            '<div style="color:#6e7681;font-size:0.82rem;font-style:italic;">Not available</div>',
            unsafe_allow_html=True,
        )


def _render_similar_incidents(incident) -> None:
    """Historical similar incidents list."""
    _section_label("Historical Context — Similar Incidents")

    similar = incident.similar_past_incidents or []
    if not similar:
        st.markdown(
            '<div style="color:#6e7681;font-size:0.82rem;font-style:italic;">No similar historical incidents.</div>',
            unsafe_allow_html=True,
        )
        return

    items_html = "".join(
        f'<div style="font-family:monospace;font-size:0.8rem;color:#79c0ff;'
        f'background:#0d1117;border:1px solid #1e2a38;border-radius:3px;'
        f'padding:4px 10px;margin-bottom:4px;">{sid}</div>'
        for sid in similar
    )
    st.markdown(items_html, unsafe_allow_html=True)


def _render_alert_breakdown(incident) -> None:
    """Alert breakdown — severity counts + expandable detail table."""
    _section_label("Alert Breakdown")

    alerts = incident.alerts or []

    if not alerts:
        st.markdown(
            '<div style="color:#6e7681;font-size:0.82rem;font-style:italic;">No alerts associated with this incident.</div>',
            unsafe_allow_html=True,
        )
        return

    # Severity count chips
    counts: dict = {}
    for a in alerts:
        sev = (a.severity or "unknown").lower()
        counts[sev] = counts.get(sev, 0) + 1

    severity_labels = sorted(
        counts.keys(),
        key=lambda s: _SEVERITY_ORDER.get(s, 0),
        reverse=True,
    )

    chips_html = ""
    for sev in severity_labels:
        colour = _SEVERITY_HEX.get(sev, "#8b949e")
        chips_html += (
            f'<div style="display:inline-block;background:#0d1117;border:1px solid {colour};'
            f'border-radius:4px;padding:6px 14px;margin-right:8px;margin-bottom:6px;text-align:center;">'
            f'<div style="font-size:0.65rem;color:#8b949e;text-transform:uppercase;letter-spacing:0.1em;">{sev}</div>'
            f'<div style="font-size:1.3rem;font-weight:800;color:{colour};">{counts[sev]}</div>'
            f'</div>'
        )
    st.markdown(chips_html, unsafe_allow_html=True)

    # Expandable detail table
    with st.expander(f"View all {len(alerts)} alert(s)"):
        for a in alerts:
            sev_c = _SEVERITY_HEX.get((a.severity or "").lower(), "#8b949e")
            st.markdown(
                f'<div style="display:flex;gap:12px;align-items:baseline;'
                f'background:#0d1117;border:1px solid #1e2a38;border-left:2px solid {sev_c};'
                f'border-radius:3px;padding:7px 12px;margin-bottom:4px;font-size:0.78rem;">'
                f'<span style="font-family:monospace;color:#79c0ff;min-width:120px;">{a.alert_id[:12]}</span>'
                f'<span style="color:{sev_c};min-width:56px;text-transform:uppercase;">{a.severity or "?"}</span>'
                f'<span style="color:#8b949e;min-width:72px;">{a.source}</span>'
                f'<span style="color:#8b949e;min-width:120px;">{a.event_type or "—"}</span>'
                f'<span style="color:#c9d1d9;">{a.asset or "—"}</span>'
                f'<span style="color:#6e7681;margin-left:auto;">{a.ip or "—"}</span>'
                f'</div>',
                unsafe_allow_html=True,
            )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def render_detection_panel(incident) -> None:
    """
    Render the Detection & Scoring panel for a single Incident.

    Safe against None/missing values on every field it reads.
    Does not crash on empty alerts or missing optional fields.
    """
    st.markdown(
        '<div style="font-size:0.72rem;color:#58a6ff;text-transform:uppercase;'
        'letter-spacing:0.12em;margin-bottom:16px;font-weight:700;">Detection & Scoring</div>',
        unsafe_allow_html=True,
    )

    _render_risk_assessment(incident)
    st.markdown("<br>", unsafe_allow_html=True)

    col_fp, col_dna = st.columns(2)
    with col_fp:
        _render_false_positive(incident)
    with col_dna:
        _render_threat_dna(incident)

    st.markdown("<br>", unsafe_allow_html=True)
    _render_similar_incidents(incident)
    st.markdown("<br>", unsafe_allow_html=True)
    _render_alert_breakdown(incident)
