"""
context_panel.py — Frontend panel for Module 3: Context & Threat Intelligence.

Usage:
    from frontend.context_panel import render_context_panel
    render_context_panel(incident)

Reads only the Context Engine fields already defined on Incident:
    incident.mitre_techniques          List[str]   e.g. ["T1110", "T1059.001"]
    incident.attack_timeline           List[dict]  e.g. [{"time": ..., "event_desc": ...}]
    incident.threat_intel              dict        e.g. {"indicators": [...], "summary": {...}}
    incident.physical_correlation      dict | None e.g. {"asset_location": ..., "correlated": ...}
    incident.predicted_next_techniques List[str]   e.g. ["T1053", "T1071"]

Never reads or invents data outside these fields.
"""

import streamlit as st

# ---------------------------------------------------------------------------
# Colour maps
# ---------------------------------------------------------------------------

# Tactic-prefix → accent hex
_TECHNIQUE_PREFIX_COLOUR = {
    "T1059": "#d97706",   # execution  – amber
    "T1078": "#7c3aed",   # credential – purple
    "T1110": "#dc2626",   # brute-force – red
    "T1068": "#b91c1c",   # privesc    – dark red
    "T1021": "#1d4ed8",   # lateral    – blue
    "T1041": "#0369a1",   # exfil      – dark blue
    "T1566": "#15803d",   # phishing   – green
    "T1204": "#92400e",   # execution  – brown
    "T1005": "#4338ca",   # collection – indigo
}
_DEFAULT_CHIP_COLOUR = "#1e2a38"

_REP_COLOUR = {
    "malicious":  "#f85149",
    "suspicious": "#e3b341",
    "clean":      "#3fb950",
}


def _chip_colour(technique_id: str) -> str:
    for prefix, colour in _TECHNIQUE_PREFIX_COLOUR.items():
        if technique_id.startswith(prefix):
            return colour
    return _DEFAULT_CHIP_COLOUR


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _section_label(text: str) -> None:
    st.markdown(
        f'<div style="font-size:0.68rem;color:#8b949e;text-transform:uppercase;'
        f'letter-spacing:0.12em;margin-bottom:8px;border-bottom:1px solid #1e2a38;'
        f'padding-bottom:5px;">{text}</div>',
        unsafe_allow_html=True,
    )


def _render_technique_chips(techniques: list, muted: bool = False) -> None:
    """Render MITRE technique IDs as inline coloured HTML chips."""
    if not techniques:
        st.markdown(
            '<div style="color:#6e7681;font-size:0.82rem;font-style:italic;">None mapped.</div>',
            unsafe_allow_html=True,
        )
        return

    border_extra = ";opacity:0.65" if muted else ""
    chips_html = " ".join(
        f'<span style="'
        f'background-color:{_chip_colour(t)};'
        f'color:#ffffff;'
        f'padding:3px 10px;'
        f'border-radius:3px;'
        f'font-size:0.78rem;'
        f'font-family:monospace;'
        f'margin:2px;'
        f'display:inline-block;'
        f'{border_extra}'
        f'">{t}</span>'
        for t in techniques
    )
    st.markdown(chips_html, unsafe_allow_html=True)


def _render_mitre_section(incident) -> None:
    """Section 1 — MITRE ATT&CK Techniques."""
    _section_label("MITRE ATT&CK Techniques")
    techniques = getattr(incident, "mitre_techniques", None) or []
    _render_technique_chips(techniques)
    if techniques:
        st.caption(f"{len(techniques)} technique(s) identified")


def _render_timeline_section(incident) -> None:
    """Section 2 — Attack Timeline."""
    _section_label("Attack Timeline")
    timeline = getattr(incident, "attack_timeline", None) or []

    if not timeline:
        st.markdown(
            '<div style="color:#6e7681;font-size:0.82rem;font-style:italic;">No attack timeline available.</div>',
            unsafe_allow_html=True,
        )
        return

    for entry in timeline:
        if not isinstance(entry, dict):
            continue
        ts         = entry.get("time") or "Unknown time"
        event_desc = entry.get("event_desc") or "Event"

        display_time = ts
        if "T" in str(ts):
            try:
                display_time = ts.split("T")[1].rstrip("Z").split("+")[0]
            except Exception:
                display_time = ts

        st.markdown(
            f'<div style="border-left:2px solid #58a6ff;padding:5px 12px;margin:4px 0;">'
            f'<div style="font-size:0.72rem;color:#8b949e;font-family:monospace;">{display_time}</div>'
            f'<div style="font-size:0.85rem;color:#c9d1d9;margin-top:2px;">{event_desc}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )


def _render_threat_intel_section(incident) -> None:
    """Section 3 — Threat Intelligence Enrichment."""
    _section_label("Threat Intelligence")
    threat_intel = getattr(incident, "threat_intel", None) or {}

    if not threat_intel:
        st.markdown(
            '<div style="color:#6e7681;font-size:0.82rem;font-style:italic;">No threat intelligence enrichment available.</div>',
            unsafe_allow_html=True,
        )
        return

    summary = threat_intel.get("summary")
    if isinstance(summary, dict):
        total_ind  = summary.get("total_indicators", 0)
        known_bad_count = summary.get("known_bad_count", 0)
        col_a, col_b = st.columns(2)
        with col_a:
            st.metric("Total Indicators", total_ind)
        with col_b:
            st.metric("Confirmed Malicious", known_bad_count)

        # Plain-language explanation of what "Known Bad" means
        if total_ind == 0:
            kb_note = "No network indicators (IPs, hashes, or domains) were extracted from this incident's alerts."
        elif known_bad_count == 0:
            kb_note = (
                f"All {total_ind} extracted indicator(s) were checked against reputation data. "
                "None were flagged as confirmed malicious by the threat intelligence enrichment. "
                "This does not mean they are safe — unresolved reputation simply means the "
                "indicator was not found in the simulated threat feed."
            )
        else:
            kb_note = (
                f"{known_bad_count} of {total_ind} indicator(s) matched confirmed malicious entries "
                "in the threat intelligence feed."
            )
        st.markdown(
            f'<div style="font-size:0.74rem;color:#8b949e;margin-top:6px;line-height:1.5;">'
            f'{kb_note}</div>',
            unsafe_allow_html=True,
        )

    indicators = threat_intel.get("indicators")
    if indicators and isinstance(indicators, list):
        with st.expander(f"View {len(indicators)} indicator(s)", expanded=False):
            for ind in indicators:
                if not isinstance(ind, dict):
                    continue
                itype     = ind.get("type", "unknown").upper()
                value     = ind.get("value", "N/A")
                rep       = (ind.get("reputation") or "unknown").lower()
                known_bad = ind.get("known_bad", False)

                rep_colour = _REP_COLOUR.get(rep, "#8b949e")
                kb_colour  = "#f85149" if known_bad else "#3fb950"

                # Human-readable reputation label
                rep_label = {
                    "malicious":  "Confirmed malicious",
                    "suspicious": "Suspicious",
                    "clean":      "Clean",
                    "unknown":    "Reputation unknown",
                }.get(rep, rep.capitalize())

                st.markdown(
                    f'<div style="display:flex;gap:10px;align-items:baseline;'
                    f'background:#0d1117;border:1px solid #1e2a38;border-left:2px solid {rep_colour};'
                    f'border-radius:3px;padding:6px 12px;margin-bottom:4px;font-size:0.78rem;">'
                    f'<span style="font-weight:700;color:#8b949e;min-width:60px;">{itype}</span>'
                    f'<span style="font-family:monospace;color:#79c0ff;flex:1;">{value}</span>'
                    f'<span style="color:{rep_colour};">{rep_label}</span>'
                    f'<span style="color:{kb_colour};min-width:100px;text-align:right;">'
                    f'{"● Confirmed bad" if known_bad else "○ Not confirmed bad"}</span>'
                    f'</div>',
                    unsafe_allow_html=True,
                )

    extra_keys = {k: v for k, v in threat_intel.items()
                  if k not in ("indicators", "summary")}
    if extra_keys:
        with st.expander("Additional threat intelligence fields", expanded=False):
            for k, v in extra_keys.items():
                st.write(f"**{k}:** {v}")


def _render_physical_section(incident) -> None:
    """Section 4 — Cyber-Physical Correlation (Geospatial/Satellite Signal)."""
    _section_label("Cyber-Physical Correlation")
    phys = getattr(incident, "physical_correlation", None)

    if not phys or not isinstance(phys, dict):
        st.markdown(
            '<div style="color:#6e7681;font-size:0.82rem;font-style:italic;">'
            'No cyber-physical correlation data available for this incident.</div>',
            unsafe_allow_html=True,
        )
        return

    correlated = phys.get("correlated", False)
    status     = phys.get("status", "")

    # ── No signal detected ────────────────────────────────────────────────
    if status == "no_physical_signal" or not correlated:
        st.markdown(
            '<div style="background:#0d1117;border:1px solid #1e2a38;border-left:2px solid #8b949e;'
            'border-radius:3px;padding:10px 14px;">'
            '<div style="font-size:0.68rem;color:#8b949e;text-transform:uppercase;'
            'letter-spacing:0.1em;margin-bottom:4px;">Geospatial / Satellite Signal</div>'
            '<div style="font-size:0.82rem;color:#8b949e;">'
            'Signal Status: <strong style="color:#c9d1d9;">Not Detected</strong></div>'
            '<div style="font-size:0.72rem;color:#6e7681;margin-top:4px;">'
            'No geospatial or satellite data was present in the alert payload for this incident.'
            '</div>'
            '</div>',
            unsafe_allow_html=True,
        )
        return

    # ── Signal detected — build fields ───────────────────────────────────
    fields = []
    if phys.get("asset"):
        fields.append(("Asset", phys["asset"], "#c9d1d9"))
    if phys.get("asset_location"):
        fields.append(("Asset Location", phys["asset_location"], "#c9d1d9"))

    # Latitude / longitude / geo if present
    for coord_key, coord_label in (("latitude", "Latitude"), ("longitude", "Longitude"), ("geo", "Geo")):
        if phys.get(coord_key) is not None:
            fields.append((coord_label, str(phys[coord_key]), "#c9d1d9"))

    # Satellite flag — always labelled consistently
    if "satellite_flag" in phys:
        sat_val = phys["satellite_flag"]
        flag_colour = "#e3b341" if sat_val else "#3fb950"
        flag_label  = "Yes — satellite data contributed to this correlation" if sat_val else "No"
        fields.append(("Satellite Data", flag_label, flag_colour))

    # Physical / geospatial signal description
    if phys.get("physical_signal"):
        fields.append(("Geospatial Signal", phys["physical_signal"], "#58a6ff"))

    # Signal status summary row (always shown when correlated)
    fields.insert(0, ("Signal Status", "Detected", "#3fb950"))

    rows_html = "".join(
        f'<div style="display:flex;gap:8px;font-size:0.82rem;padding:5px 0;border-bottom:1px solid #1e2a38;">'
        f'<span style="color:#8b949e;min-width:130px;font-size:0.72rem;text-transform:uppercase;'
        f'letter-spacing:0.06em;">{label}</span>'
        f'<span style="color:{colour};">{val}</span>'
        f'</div>'
        for label, val, colour in fields
    )

    st.markdown(
        f'<div style="background:#0d1117;border:1px solid #1e2a38;border-left:2px solid #58a6ff;'
        f'border-radius:3px;padding:10px 14px;">'
        f'<div style="font-size:0.68rem;color:#8b949e;text-transform:uppercase;'
        f'letter-spacing:0.1em;margin-bottom:6px;">Geospatial / Satellite Signal</div>'
        f'{rows_html}</div>',
        unsafe_allow_html=True,
    )

    if phys.get("correlation"):
        st.markdown(
            f'<div style="font-size:0.74rem;color:#8b949e;margin-top:6px;line-height:1.5;">'
            f'{phys["correlation"]}</div>',
            unsafe_allow_html=True,
        )

    shown = {"asset", "asset_location", "satellite_flag",
              "physical_signal", "correlation", "correlated", "status",
              "latitude", "longitude", "geo"}
    extras = {k: v for k, v in phys.items() if k not in shown}
    if extras:
        with st.expander("Additional geospatial fields", expanded=False):
            for k, v in extras.items():
                st.write(f"**{k}:** {v}")


def _render_predicted_section(incident) -> None:
    """Section 5 — Predicted Next Techniques."""
    _section_label("Predicted Next Techniques")
    predicted = getattr(incident, "predicted_next_techniques", None) or []

    if not predicted:
        st.markdown(
            '<div style="color:#6e7681;font-size:0.82rem;font-style:italic;">No predicted techniques available.</div>',
            unsafe_allow_html=True,
        )
        return

    _render_technique_chips(predicted, muted=True)
    st.caption(
        "Predicted based on observed kill-chain progression. "
        "Not confirmed activity."
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def render_context_panel(incident) -> None:
    """
    Render the Context & Threat Intelligence panel for a single Incident.

    Safe against None / empty / missing values on every field it reads.
    Does not crash regardless of what the backend has populated.
    """
    st.markdown(
        '<div style="font-size:0.72rem;color:#58a6ff;text-transform:uppercase;'
        'letter-spacing:0.12em;margin-bottom:16px;font-weight:700;">Context Intelligence</div>',
        unsafe_allow_html=True,
    )

    col_left, col_right = st.columns([1, 1])

    with col_left:
        _render_mitre_section(incident)
        st.markdown("<br>", unsafe_allow_html=True)
        _render_timeline_section(incident)

    with col_right:
        _render_threat_intel_section(incident)
        st.markdown("<br>", unsafe_allow_html=True)
        _render_physical_section(incident)

    st.markdown("---")
    _render_predicted_section(incident)
