import streamlit as st
import sys
import os
from datetime import datetime

# Make sure src/ is on the path so imports work regardless of where streamlit is run from
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import run_pipeline
from frontend.detection_panel import render_detection_panel
from frontend.context_panel import render_context_panel
from frontend.reasoning_panel import render_reasoning_panel

st.set_page_config(
    page_title="Threat Intelligence Command Center",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Global CSS — dark command-center aesthetic
# ---------------------------------------------------------------------------
st.markdown("""
<style>
    /* ── Base ── */
    html, body, [data-testid="stAppViewContainer"] {
        background-color: #080c12 !important;
        color: #c9d1d9 !important;
    }
    [data-testid="stMain"] {
        background-color: #080c12 !important;
    }
    .block-container {
        padding-top: 0.6rem !important;
        padding-bottom: 2rem !important;
        max-width: 1400px !important;
    }

    /* ── Sidebar ── */
    section[data-testid="stSidebar"] {
        background-color: #0d1117 !important;
        border-right: 1px solid #1e2a38 !important;
    }
    /* Broad sidebar mute — excluded from chip elements so chip rules win.
       Excludes BOTH the old data-baseweb attribute AND the current data-tag
       attribute, since Streamlit/BaseWeb versions differ on which is used. */
    section[data-testid="stSidebar"] *:not([data-tag]):not([data-tag] *):not(span[data-baseweb="tag"]):not(span[data-baseweb="tag"] *) {
        color: #8b949e !important;
    }
    section[data-testid="stSidebar"] h1,
    section[data-testid="stSidebar"] h2,
    section[data-testid="stSidebar"] h3 {
        color: #58a6ff !important;
        font-size: 0.68rem !important;
        letter-spacing: 0.14em !important;
        text-transform: uppercase !important;
        border-bottom: 1px solid #1e2a38 !important;
        padding-bottom: 5px !important;
        margin-bottom: 6px !important;
        margin-top: 4px !important;
    }
    section[data-testid="stSidebar"] label {
        font-size: 0.76rem !important;
        color: #8b949e !important;
    }
    section[data-testid="stSidebar"] [data-testid="stRadio"] label {
        font-size: 0.82rem !important;
        padding: 2px 0 !important;
    }

    /* ── Tabs ── */
    [data-testid="stTabs"] [role="tablist"] {
        border-bottom: 1px solid #1e2a38 !important;
        gap: 0 !important;
    }
    [data-testid="stTabs"] [role="tab"] {
        background: transparent !important;
        color: #8b949e !important;
        font-size: 0.78rem !important;
        font-weight: 600 !important;
        letter-spacing: 0.07em !important;
        text-transform: uppercase !important;
        border: none !important;
        border-bottom: 2px solid transparent !important;
        padding: 7px 18px !important;
        margin-right: 2px !important;
    }
    [data-testid="stTabs"] [role="tab"][aria-selected="true"] {
        color: #58a6ff !important;
        border-bottom: 2px solid #58a6ff !important;
        background: transparent !important;
    }
    [data-testid="stTabs"] [role="tab"]:hover {
        color: #c9d1d9 !important;
        background: #0d1117 !important;
    }

    /* ── Expander ── */
    div[data-testid="stExpander"] {
        background-color: #0d1117 !important;
        border: 1px solid #1e2a38 !important;
        border-radius: 4px !important;
        margin-bottom: 6px !important;
    }
    div[data-testid="stExpander"] summary {
        font-size: 0.82rem !important;
        font-weight: 600 !important;
        color: #8b949e !important;
        padding: 5px 4px !important;
    }

    /* ── Metrics ── */
    div[data-testid="stMetric"] {
        background-color: #0d1117 !important;
        border: 1px solid #1e2a38 !important;
        border-radius: 4px !important;
        padding: 12px 16px !important;
    }
    div[data-testid="stMetricLabel"] {
        font-size: 0.68rem !important;
        text-transform: uppercase !important;
        letter-spacing: 0.1em !important;
        color: #8b949e !important;
    }
    div[data-testid="stMetricValue"] {
        font-size: 1.6rem !important;
        font-weight: 700 !important;
        color: #c9d1d9 !important;
    }

    /* ── Progress bar ── */
    div[data-testid="stProgressBar"] > div {
        background-color: #58a6ff !important;
    }

    /* ── Horizontal rule ── */
    hr {
        border-color: #1e2a38 !important;
        margin: 0.75rem 0 !important;
    }

    /* ── Code blocks ── */
    code, pre {
        background-color: #0d1117 !important;
        color: #79c0ff !important;
        border: 1px solid #1e2a38 !important;
        font-size: 0.8rem !important;
    }

    /* ── Alerts ── */
    div[data-testid="stAlert"] {
        border-radius: 4px !important;
    }

    /* ── Buttons ── */
    button[kind="secondary"] {
        background-color: #0d1117 !important;
        border: 1px solid #1e2a38 !important;
        color: #58a6ff !important;
        font-size: 0.76rem !important;
        font-weight: 600 !important;
        letter-spacing: 0.05em !important;
        padding: 4px 12px !important;
        border-radius: 3px !important;
    }
    button[kind="secondary"]:hover {
        border-color: #58a6ff !important;
        color: #79c0ff !important;
    }

    /* ── Inputs ── */
    div[data-testid="stTextInput"] input {
        background-color: #0d1117 !important;
        border: 1px solid #1e2a38 !important;
        color: #c9d1d9 !important;
        font-size: 0.85rem !important;
    }

    /* ── Generic text ── */
    p, li { font-size: 0.86rem !important; }
    h3 { color: #c9d1d9 !important; font-size: 0.95rem !important; font-weight: 700 !important; }
    h4 { color: #8b949e !important; font-size: 0.84rem !important; font-weight: 600 !important;
         text-transform: uppercase !important; letter-spacing: 0.07em !important; }

    /* ── Selectbox ── */
    div[data-testid="stSelectbox"] > div > div {
        background-color: #0d1117 !important;
        border: 1px solid #1e2a38 !important;
        color: #c9d1d9 !important;
    }

    /* ── Multiselect selected-value chips (sidebar) ──────────────────────
       FIXED: newer Streamlit/BaseWeb uses a boolean `data-tag` attribute
       on the chip span, NOT `data-baseweb="tag"`. We target both so this
       works regardless of Streamlit version. -webkit-text-fill-color is
       set alongside color because Chromium/Edge can ignore color alone
       when the BaseWeb theme sets the webkit prop directly. */
    span[data-tag],
    span[data-baseweb="tag"] {
        background-color: #2563eb !important;
        border: 1px solid #3b82f6 !important;
        border-radius: 4px !important;
        padding: 3px 8px !important;
        margin: 2px 3px 2px 0 !important;
        opacity: 1 !important;
    }
    span[data-tag],
    span[data-tag] *,
    span[data-baseweb="tag"],
    span[data-baseweb="tag"] * {
        color: #ffffff !important;
        -webkit-text-fill-color: #ffffff !important;
        opacity: 1 !important;
    }
    span[data-tag] span[title],
    span[data-baseweb="tag"] span[title] {
        font-size: 0.76rem !important;
        font-weight: 600 !important;
        white-space: nowrap !important;
        letter-spacing: 0.02em !important;
        color: #ffffff !important;
        -webkit-text-fill-color: #ffffff !important;
    }
    span[data-tag] button,
    span[data-baseweb="tag"] button {
        color: #ffffff !important;
        opacity: 0.85 !important;
    }
    span[data-tag] button:hover,
    span[data-baseweb="tag"] button:hover {
        opacity: 1 !important;
    }
    span[data-tag] svg,
    span[data-baseweb="tag"] svg {
        fill: #ffffff !important;
    }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Pipeline — cached; refresh clears the cache and reruns
# ---------------------------------------------------------------------------
@st.cache_data
def load_incidents():
    sample_sources = ["siem", "sensor", "intel", "satellite"]
    return run_pipeline(sample_sources)


incidents = load_incidents()

# ---------------------------------------------------------------------------
# Priority colour palette
# ---------------------------------------------------------------------------
_PRI_COLOUR = {
    "Critical": "#f85149",
    "High":     "#e3b341",
    "Medium":   "#58a6ff",
    "Low":      "#3fb950",
}


def _pri_hex(priority):
    return _PRI_COLOUR.get(priority or "", "#8b949e")


# ---------------------------------------------------------------------------
# Sidebar — navigation + filters
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### COMMAND CENTER")
    nav = st.radio(
        " ",
        options=["Overview", "Incidents", "Detection & Scoring", "Context Intelligence", "AI Reasoning"],
        label_visibility="collapsed",
    )

    st.markdown("---")
    st.markdown("### FILTERS")

    priority_filter = st.multiselect(
        "Priority",
        options=["Critical", "High", "Medium", "Low"],
        default=["Critical", "High", "Medium", "Low"],
    )
    status_filter = st.multiselect(
        "Status",
        options=["new", "investigating", "closed"],
        default=["new", "investigating", "closed"],
    )
    sources_available = sorted({
        a.source for inc in incidents for a in (inc.alerts or [])
    })
    source_filter = st.multiselect(
        "Source",
        options=sources_available,
        default=sources_available,
    )

    st.markdown("---")
    # System status + per-source alert counts
    _src_counts = {}
    for _inc in incidents:
        for _a in (_inc.alerts or []):
            _src_counts[_a.source] = _src_counts.get(_a.source, 0) + 1
    _src_lines = "".join(
        f'<div style="display:flex;justify-content:space-between;'
        f'font-size:0.63rem;color:#6e7681;padding:1px 0;">'
        f'<span style="text-transform:uppercase;letter-spacing:0.06em;">{s}</span>'
        f'<span style="color:#8b949e;">{c} alerts</span></div>'
        for s, c in sorted(_src_counts.items())
    )
    st.markdown(
        '<div style="font-size:0.68rem;color:#3fb950;letter-spacing:0.1em;'
        'margin-bottom:6px;font-weight:600;">● SYSTEM OPERATIONAL</div>'
        '<div style="font-size:0.63rem;color:#6e7681;letter-spacing:0.06em;'
        'margin-bottom:8px;">THREAT MONITORING ACTIVE</div>'
        f'<div style="border-top:1px solid #1e2a38;padding-top:8px;">'
        f'<div style="font-size:0.6rem;color:#6e7681;text-transform:uppercase;'
        f'letter-spacing:0.12em;margin-bottom:4px;">Data Sources</div>'
        f'{_src_lines}</div>',
        unsafe_allow_html=True,
    )

# ---------------------------------------------------------------------------
# Apply filters
# ---------------------------------------------------------------------------
filtered = [
    inc for inc in incidents
    if inc.priority in priority_filter
    and (inc.status or "new") in status_filter
    and (not inc.alerts or any(a.source in source_filter for a in inc.alerts))
]

# ---------------------------------------------------------------------------
# Pre-compute global metrics (used in header + overview)
# ---------------------------------------------------------------------------
total      = len(incidents)
n_critical = sum(1 for i in incidents if i.priority == "Critical")
n_high     = sum(1 for i in incidents if i.priority == "High")
n_medium   = sum(1 for i in incidents if i.priority == "Medium")
n_low      = sum(1 for i in incidents if i.priority == "Low")
avg_risk   = round(sum((i.risk_score or 0) for i in incidents) / total, 1) if total else 0

# Active = not closed
n_active = sum(1 for i in incidents if (i.status or "new") != "closed")

# Threat level — deterministic from data
if n_critical >= 1:
    threat_level       = "CRITICAL"
    threat_level_hex   = "#f85149"
    threat_level_dot   = "●"
elif n_high >= 2 or avg_risk >= 70:
    threat_level       = "ELEVATED"
    threat_level_hex   = "#e3b341"
    threat_level_dot   = "●"
elif n_medium >= 2 or avg_risk >= 40:
    threat_level       = "GUARDED"
    threat_level_hex   = "#58a6ff"
    threat_level_dot   = "●"
else:
    threat_level       = "LOW"
    threat_level_hex   = "#3fb950"
    threat_level_dot   = "●"

last_refresh = datetime.now().strftime("%H:%M:%S")

# ---------------------------------------------------------------------------
# COMMAND-CENTER HEADER
# ---------------------------------------------------------------------------
col_title, col_meta = st.columns([3, 1])

with col_title:
    st.markdown(
        '<div style="padding:12px 0 10px 0;">'
        '<div style="font-size:0.64rem;color:#6e7681;letter-spacing:0.18em;'
        'text-transform:uppercase;margin-bottom:5px;">IBM · ByteForge Hackathon</div>'
        '<div style="font-size:1.45rem;font-weight:800;color:#c9d1d9;'
        'letter-spacing:0.01em;line-height:1.15;">&#9705; Threat Intelligence Command Center</div>'
        '<div style="font-size:0.79rem;color:#6e7681;margin-top:4px;">'
        'Multi-source threat correlation, prioritisation &amp; AI-assisted investigation'
        '</div>'
        '</div>',
        unsafe_allow_html=True,
    )

with col_meta:
    st.markdown(
        f'<div style="display:flex;flex-direction:column;align-items:flex-end;'
        f'justify-content:center;padding:12px 0 10px 0;gap:4px;">'
        f'<div style="font-size:0.68rem;color:#3fb950;letter-spacing:0.1em;font-weight:600;">'
        f'● SYSTEM OPERATIONAL</div>'
        f'<div style="font-size:0.64rem;color:#6e7681;letter-spacing:0.08em;">'
        f'LAST REFRESH: {last_refresh}</div>'
        f'<div style="font-size:0.64rem;color:#6e7681;letter-spacing:0.08em;">'
        f'INCIDENTS MONITORED: {total}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )
    if st.button("↻ Refresh", key="_global_refresh"):
        st.cache_data.clear()
        st.rerun()

# Separator after header
st.markdown(
    '<div style="border-bottom:1px solid #1e2a38;margin-bottom:14px;"></div>',
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# CURRENT THREAT PICTURE  — shown on ALL pages
# ---------------------------------------------------------------------------
st.markdown(
    f'<div style="background:#0d1117;border:1px solid #1e2a38;'
    f'border-left:3px solid {threat_level_hex};border-radius:4px;'
    f'padding:10px 20px;margin-bottom:12px;">'
    f'<div style="display:flex;align-items:center;gap:32px;flex-wrap:wrap;">'

    f'<div style="min-width:120px;">'
    f'<div style="font-size:0.58rem;color:#6e7681;text-transform:uppercase;'
    f'letter-spacing:0.14em;margin-bottom:3px;">Current Threat Picture</div>'
    f'<div style="font-size:1.2rem;font-weight:800;color:{threat_level_hex};'
    f'letter-spacing:0.06em;line-height:1.2;">{threat_level_dot} {threat_level}</div>'
    f'</div>'

    f'<div style="width:1px;height:36px;background:#1e2a38;flex-shrink:0;"></div>'

    f'<div style="display:flex;gap:32px;">'

    f'<div>'
    f'<div style="font-size:0.58rem;color:#6e7681;text-transform:uppercase;'
    f'letter-spacing:0.1em;margin-bottom:2px;">Total</div>'
    f'<div style="font-size:1.15rem;font-weight:800;color:#58a6ff;">{total}</div>'
    f'</div>'

    f'<div>'
    f'<div style="font-size:0.58rem;color:#6e7681;text-transform:uppercase;'
    f'letter-spacing:0.1em;margin-bottom:2px;">Active</div>'
    f'<div style="font-size:1.15rem;font-weight:800;color:#c9d1d9;">{n_active}</div>'
    f'</div>'

    f'<div>'
    f'<div style="font-size:0.58rem;color:#6e7681;text-transform:uppercase;'
    f'letter-spacing:0.1em;margin-bottom:2px;">Avg Risk</div>'
    f'<div style="font-size:1.15rem;font-weight:800;color:#bc8cff;">{avg_risk}</div>'
    f'</div>'

    f'</div>'
    f'</div>'
    f'</div>',
    unsafe_allow_html=True,
)


# ===========================================================================
# OVERVIEW PAGE
# ===========================================================================
if nav == "Overview":

    def _kpi(label, value, colour):
        st.markdown(
            f'<div style="background:#0d1117;border:1px solid #1e2a38;'
            f'border-top:2px solid {colour};border-radius:4px;'
            f'padding:11px 16px;height:100%;">'
            f'<div style="font-size:0.6rem;color:#6e7681;text-transform:uppercase;'
            f'letter-spacing:0.12em;margin-bottom:4px;">{label}</div>'
            f'<div style="font-size:1.7rem;font-weight:800;color:{colour};'
            f'line-height:1.1;">{value}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

    c1, c2, c3, c4, c5, c6 = st.columns(6)
    with c1: _kpi("Total",          total,      "#58a6ff")
    with c2: _kpi("Critical",       n_critical, "#f85149")
    with c3: _kpi("High",           n_high,     "#e3b341")
    with c4: _kpi("Medium",         n_medium,   "#58a6ff")
    with c5: _kpi("Low",            n_low,      "#3fb950")
    with c6: _kpi("Avg Risk",       avg_risk,   "#bc8cff")

    st.markdown('<div style="margin-bottom:10px;"></div>', unsafe_allow_html=True)

    st.markdown(
        '<div style="font-size:0.62rem;color:#6e7681;text-transform:uppercase;'
        'letter-spacing:0.14em;margin-bottom:8px;">Threat Priority Distribution</div>',
        unsafe_allow_html=True,
    )

    _dist_rows = [
        ("Critical", n_critical, "#f85149"),
        ("High",     n_high,     "#e3b341"),
        ("Medium",   n_medium,   "#58a6ff"),
        ("Low",      n_low,      "#3fb950"),
    ]
    _max_count = max((r[1] for r in _dist_rows), default=1) or 1

    dist_html = '<div style="background:#0d1117;border:1px solid #1e2a38;border-radius:4px;padding:12px 16px;">'
    for label, count, colour in _dist_rows:
        bar_pct = int((count / _max_count) * 100)
        dist_html += (
            f'<div style="display:flex;align-items:center;gap:10px;margin-bottom:7px;">'
            f'<div style="width:54px;font-size:0.7rem;color:{colour};font-weight:600;'
            f'text-transform:uppercase;letter-spacing:0.06em;">{label}</div>'
            f'<div style="flex:1;height:10px;background:#1e2a38;border-radius:2px;overflow:hidden;">'
            f'<div style="width:{bar_pct}%;height:100%;background:{colour};border-radius:2px;"></div>'
            f'</div>'
            f'<div style="width:22px;text-align:right;font-size:0.78rem;font-weight:700;color:{colour};">{count}</div>'
            f'</div>'
        )
    dist_html += '</div>'
    st.markdown(dist_html, unsafe_allow_html=True)

    st.markdown('<div style="margin-bottom:12px;"></div>', unsafe_allow_html=True)

    sorted_filtered = sorted(
        filtered,
        key=lambda i: (i.risk_score or 0),
        reverse=True,
    )

    st.markdown(
        f'<div style="font-size:0.62rem;color:#6e7681;text-transform:uppercase;'
        f'letter-spacing:0.14em;margin-bottom:6px;">'
        f'Active Incidents — {len(sorted_filtered)} matching filters</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        '<div style="display:flex;align-items:center;gap:0;'
        'padding:4px 16px;margin-bottom:2px;">'
        '<div style="width:72px;font-size:0.6rem;color:#6e7681;text-transform:uppercase;letter-spacing:0.1em;">Priority</div>'
        '<div style="width:52px;font-size:0.6rem;color:#6e7681;text-transform:uppercase;letter-spacing:0.1em;text-align:right;">Risk</div>'
        '<div style="width:16px;"></div>'
        '<div style="flex:1;font-size:0.6rem;color:#6e7681;text-transform:uppercase;letter-spacing:0.1em;">Incident</div>'
        '<div style="width:70px;font-size:0.6rem;color:#6e7681;text-transform:uppercase;letter-spacing:0.1em;">Alerts</div>'
        '<div style="min-width:100px;font-size:0.6rem;color:#6e7681;text-transform:uppercase;letter-spacing:0.1em;">Asset</div>'
        '<div style="min-width:130px;font-size:0.6rem;color:#6e7681;text-transform:uppercase;letter-spacing:0.1em;">Source</div>'
        '<div style="width:88px;font-size:0.6rem;color:#6e7681;text-transform:uppercase;letter-spacing:0.1em;text-align:right;">Status</div>'
        '</div>',
        unsafe_allow_html=True,
    )

    for inc in sorted_filtered[:10]:
        colour    = _pri_hex(inc.priority)
        sources   = sorted({a.source for a in (inc.alerts or [])})
        src_str   = " · ".join(sources) if sources else "—"
        n_alerts  = len(inc.alerts or [])
        asset     = next((a.asset for a in (inc.alerts or []) if a.asset), "—")
        risk_disp = f"{round(float(inc.risk_score), 1)}" if inc.risk_score is not None else "—"
        status    = (inc.status or "new").upper()

        st.markdown(
            f'<div class="inc-row" style="display:flex;align-items:center;gap:0;'
            f'background:#0d1117;border:1px solid #1e2a38;border-left:3px solid {colour};'
            f'border-radius:3px;padding:8px 16px;margin-bottom:4px;'
            f'transition:background 0.12s,border-color 0.12s;">'
            f'<div style="width:72px;font-size:0.7rem;font-weight:700;color:{colour};'
            f'text-transform:uppercase;letter-spacing:0.06em;">{inc.priority or "—"}</div>'
            f'<div style="width:52px;text-align:right;font-size:0.92rem;font-weight:800;color:{colour};">{risk_disp}</div>'
            f'<div style="width:16px;"></div>'
            f'<div style="flex:1;font-family:monospace;font-size:0.78rem;color:#8b949e;">'
            f'#{inc.incident_id[:8]}</div>'
            f'<div style="width:70px;font-size:0.78rem;color:#8b949e;">{n_alerts} alerts</div>'
            f'<div style="min-width:100px;font-size:0.78rem;color:#8b949e;">{asset}</div>'
            f'<div style="min-width:130px;font-size:0.72rem;color:#6e7681;">{src_str}</div>'
            f'<div style="width:88px;text-align:right;font-size:0.68rem;color:#8b949e;'
            f'text-transform:uppercase;letter-spacing:0.08em;">{status}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

    if len(sorted_filtered) > 10:
        st.caption(f"↳ {len(sorted_filtered) - 10} more — switch to **Incidents** view to see all")


# ===========================================================================
# INCIDENTS PAGE
# ===========================================================================
elif nav == "Incidents":

    sorted_filtered = sorted(
        filtered,
        key=lambda i: (i.risk_score or 0),
        reverse=True,
    )

    st.markdown(
        f'<div style="font-size:0.62rem;color:#6e7681;text-transform:uppercase;'
        f'letter-spacing:0.14em;margin-bottom:10px;">'
        f'Incidents — {len(sorted_filtered)} matching filters</div>',
        unsafe_allow_html=True,
    )

    if not sorted_filtered:
        st.info("No incidents match the current filters.")
    else:
        for inc in sorted_filtered:
            colour    = _pri_hex(inc.priority)
            sources   = sorted({a.source for a in (inc.alerts or [])})
            src_str   = " · ".join(sources) if sources else "—"
            n_alerts  = len(inc.alerts or [])
            asset     = next((a.asset for a in (inc.alerts or []) if a.asset), "—")
            risk_disp = f"{round(float(inc.risk_score), 1)}" if inc.risk_score is not None else "—"
            status    = (inc.status or "new").upper()

            card_label = (
                f"{inc.priority or '—'}  ·  Risk {risk_disp}  ·  "
                f"#{inc.incident_id[:8]}  ·  {n_alerts} alerts  ·  {status}"
            )

            with st.expander(card_label, expanded=False):
                st.markdown(
                    f'<div style="display:flex;align-items:center;gap:18px;'
                    f'background:#080c12;border:1px solid #1e2a38;border-left:3px solid {colour};'
                    f'border-radius:3px;padding:10px 16px;margin-bottom:14px;">'

                    f'<div style="min-width:64px;">'
                    f'<div style="font-size:0.58rem;color:#6e7681;text-transform:uppercase;'
                    f'letter-spacing:0.12em;">Priority</div>'
                    f'<div style="font-size:0.82rem;font-weight:800;color:{colour};'
                    f'text-transform:uppercase;letter-spacing:0.06em;">{inc.priority or "—"}</div>'
                    f'</div>'

                    f'<div style="min-width:60px;">'
                    f'<div style="font-size:0.58rem;color:#6e7681;text-transform:uppercase;'
                    f'letter-spacing:0.12em;">Risk</div>'
                    f'<div style="font-size:1.4rem;font-weight:800;color:{colour};line-height:1.1;">{risk_disp}</div>'
                    f'</div>'

                    f'<div style="width:1px;height:36px;background:#1e2a38;"></div>'

                    f'<div style="flex:1;">'
                    f'<div style="font-family:monospace;font-size:0.88rem;font-weight:700;'
                    f'color:#c9d1d9;letter-spacing:0.02em;">'
                    f'INCIDENT #{inc.incident_id[:8].upper()}</div>'
                    f'<div style="font-size:0.72rem;color:#6e7681;margin-top:3px;">'
                    f'{n_alerts} ALERTS&nbsp;&nbsp;·&nbsp;&nbsp;{asset}&nbsp;&nbsp;·&nbsp;&nbsp;{src_str}'
                    f'</div>'
                    f'</div>'

                    f'<div style="text-align:right;">'
                    f'<div style="font-size:0.58rem;color:#6e7681;text-transform:uppercase;'
                    f'letter-spacing:0.12em;">Status</div>'
                    f'<div style="font-size:0.78rem;font-weight:600;color:#8b949e;'
                    f'text-transform:uppercase;letter-spacing:0.08em;">{status}</div>'
                    f'</div>'

                    f'</div>',
                    unsafe_allow_html=True,
                )

                tab_det, tab_ctx, tab_ai = st.tabs([
                    "Detection & Scoring",
                    "Context Intelligence",
                    "AI Reasoning",
                ])
                with tab_det:
                    render_detection_panel(inc)
                with tab_ctx:
                    render_context_panel(inc)
                with tab_ai:
                    render_reasoning_panel(inc)


# ===========================================================================
# SINGLE-PANEL PAGES  (Detection / Context / Reasoning)
# ===========================================================================
else:
    if not filtered:
        st.info("No incidents match the current filters.")
    else:
        sorted_filtered = sorted(
            filtered,
            key=lambda i: (i.risk_score or 0),
            reverse=True,
        )

        inc_options = {
            f"#{inc.incident_id[:8].upper()}  ·  {inc.priority}  ·  Risk {round(float(inc.risk_score), 1) if inc.risk_score is not None else '—'}": inc
            for inc in sorted_filtered
        }
        selected_label = st.selectbox(
            "Select Incident",
            options=list(inc_options.keys()),
            label_visibility="visible",
        )
        inc = inc_options[selected_label]

        colour    = _pri_hex(inc.priority)
        sources   = sorted({a.source for a in (inc.alerts or [])})
        src_str   = " · ".join(sources) if sources else "—"
        n_alerts  = len(inc.alerts or [])
        asset     = next((a.asset for a in (inc.alerts or []) if a.asset), "—")
        risk_disp = f"{round(float(inc.risk_score), 1)}" if inc.risk_score is not None else "—"
        status    = (inc.status or "new").upper()

        st.markdown(
            f'<div style="display:flex;align-items:center;gap:18px;'
            f'background:#0d1117;border:1px solid #1e2a38;border-left:3px solid {colour};'
            f'border-radius:3px;padding:10px 16px;margin-bottom:16px;">'

            f'<div style="min-width:64px;">'
            f'<div style="font-size:0.58rem;color:#6e7681;text-transform:uppercase;'
            f'letter-spacing:0.12em;">Priority</div>'
            f'<div style="font-size:0.82rem;font-weight:800;color:{colour};'
            f'text-transform:uppercase;letter-spacing:0.06em;">{inc.priority or "—"}</div>'
            f'</div>'

            f'<div style="min-width:60px;">'
            f'<div style="font-size:0.58rem;color:#6e7681;text-transform:uppercase;'
            f'letter-spacing:0.12em;">Risk</div>'
            f'<div style="font-size:1.4rem;font-weight:800;color:{colour};line-height:1.1;">{risk_disp}</div>'
            f'</div>'

            f'<div style="width:1px;height:36px;background:#1e2a38;"></div>'

            f'<div style="flex:1;">'
            f'<div style="font-family:monospace;font-size:0.88rem;font-weight:700;'
            f'color:#c9d1d9;letter-spacing:0.02em;">'
            f'INCIDENT #{inc.incident_id[:8].upper()}</div>'
            f'<div style="font-size:0.72rem;color:#6e7681;margin-top:3px;">'
            f'{n_alerts} ALERTS&nbsp;&nbsp;·&nbsp;&nbsp;{asset}&nbsp;&nbsp;·&nbsp;&nbsp;{src_str}'
            f'</div>'
            f'</div>'

            f'<div style="text-align:right;">'
            f'<div style="font-size:0.58rem;color:#6e7681;text-transform:uppercase;'
            f'letter-spacing:0.12em;">Status</div>'
            f'<div style="font-size:0.78rem;font-weight:600;color:#8b949e;'
            f'text-transform:uppercase;letter-spacing:0.08em;">{status}</div>'
            f'</div>'

            f'</div>',
            unsafe_allow_html=True,
        )

        if nav == "Detection & Scoring":
            render_detection_panel(inc)
        elif nav == "Context Intelligence":
            render_context_panel(inc)
        elif nav == "AI Reasoning":
            render_reasoning_panel(inc)