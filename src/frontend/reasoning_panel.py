"""
reasoning_panel.py — Frontend panel for Module 4: AI Reasoning & Reporting.

Usage:
    from frontend.reasoning_panel import render_reasoning_panel
    render_reasoning_panel(incident)

Reads only the Reasoning fields already defined on Incident:
    incident.ai_explanation            str | None
    incident.bluf_report               dict | None  keys: threat, impact,
                                                         confidence, evidence,
                                                         next_steps (list[str])
    incident.recommended_actions       list[str]
    incident.predicted_next_techniques list[str]

Also reads (read-only, never written):
    incident.priority                  str | None
    incident.risk_score                float | None
    incident.mitre_techniques          list[str]

Analyst Q&A delegates to the existing local function:
    reasoning.ai_assistant.answer_analyst_question(incident, question) -> str

No external APIs, no LLMs, no fabricated data.
"""

import streamlit as st

# ---------------------------------------------------------------------------
# Import the local Q&A function — degrade gracefully if unavailable
# ---------------------------------------------------------------------------
try:
    from reasoning.ai_assistant import answer_analyst_question as _qa_fn
    _QA_AVAILABLE = True
except Exception:
    _QA_AVAILABLE = False
    _qa_fn = None   # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------
_CONFIDENCE_COLOUR = {
    "high":   "#3fb950",
    "medium": "#e3b341",
    "low":    "#f85149",
}

_PRIORITY_HEX = {
    "Critical": "#f85149",
    "High":     "#e3b341",
    "Medium":   "#58a6ff",
    "Low":      "#3fb950",
}

_TECH_COLOURS = {
    "T1059": "#d97706",
    "T1078": "#7c3aed",
    "T1110": "#dc2626",
    "T1068": "#b91c1c",
    "T1021": "#1d4ed8",
    "T1041": "#0369a1",
    "T1566": "#15803d",
    "T1204": "#92400e",
    "T1005": "#4338ca",
    "T1547": "#0f766e",
}
_DEFAULT_TECH_COLOUR = "#1e2a38"


def _tech_chip_colour(tid: str) -> str:
    for prefix, colour in _TECH_COLOURS.items():
        if tid.startswith(prefix):
            return colour
    return _DEFAULT_TECH_COLOUR


def _pri_hex(priority: str) -> str:
    return _PRIORITY_HEX.get(priority or "", "#8b949e")


# ---------------------------------------------------------------------------
# Section label helper
# ---------------------------------------------------------------------------

def _section_label(text: str) -> None:
    st.markdown(
        f'<div style="font-size:0.68rem;color:#8b949e;text-transform:uppercase;'
        f'letter-spacing:0.12em;margin-bottom:8px;border-bottom:1px solid #1e2a38;'
        f'padding-bottom:5px;">{text}</div>',
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Tech chip renderer
# ---------------------------------------------------------------------------

def _render_tech_chips(techniques: list) -> None:
    """Render technique IDs as inline coloured HTML chips."""
    if not techniques:
        st.markdown(
            '<div style="color:#6e7681;font-size:0.82rem;font-style:italic;">No predictions available.</div>',
            unsafe_allow_html=True,
        )
        return
    chips = " ".join(
        f'<span style="background:{_tech_chip_colour(t)};color:#fff;'
        f'padding:3px 10px;border-radius:3px;font-size:0.78rem;'
        f'font-family:monospace;margin:2px;display:inline-block;opacity:0.8;">{t}</span>'
        for t in techniques
    )
    st.markdown(chips, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------

def _render_ai_explanation(incident) -> None:
    """Section 1 — AI Investigation Explanation."""
    _section_label("AI Investigation Explanation")
    explanation = getattr(incident, "ai_explanation", None)
    if explanation:
        st.markdown(
            f'<div style="background:#0d1117;border:1px solid #1e2a38;border-left:2px solid #58a6ff;'
            f'border-radius:3px;padding:12px 16px;font-size:0.86rem;color:#c9d1d9;line-height:1.6;">'
            f'{explanation}</div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<div style="color:#6e7681;font-size:0.82rem;font-style:italic;">AI explanation not available.</div>',
            unsafe_allow_html=True,
        )


def _render_bluf_report(incident) -> None:
    """Section 2 — BLUF Report (Bottom Line Up Front)."""
    _section_label("BLUF Report")
    bluf = getattr(incident, "bluf_report", None)

    if not bluf or not isinstance(bluf, dict):
        st.markdown(
            '<div style="color:#6e7681;font-size:0.82rem;font-style:italic;">BLUF report not available.</div>',
            unsafe_allow_html=True,
        )
        return

    confidence = (bluf.get("confidence") or "unknown").lower()
    conf_colour = _CONFIDENCE_COLOUR.get(confidence, "#8b949e")

    threat = bluf.get("threat")
    impact = bluf.get("impact")

    if threat or impact:
        st.markdown(
            f'<div style="background:#0d1117;border:1px solid #1e2a38;border-radius:4px;padding:14px 16px;margin-bottom:10px;">'
            + (
                f'<div style="margin-bottom:8px;">'
                f'<div style="font-size:0.65rem;color:#8b949e;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:3px;">Threat</div>'
                f'<div style="font-size:0.86rem;color:#c9d1d9;">{threat}</div>'
                f'</div>'
                if threat else ""
            )
            + (
                f'<div style="margin-bottom:4px;">'
                f'<div style="font-size:0.65rem;color:#8b949e;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:3px;">Impact</div>'
                f'<div style="font-size:0.86rem;color:#c9d1d9;">{impact}</div>'
                f'</div>'
                if impact else ""
            )
            + f'<div style="margin-top:10px;padding-top:8px;border-top:1px solid #1e2a38;">'
            f'<span style="font-size:0.65rem;color:#8b949e;text-transform:uppercase;letter-spacing:0.1em;">Confidence</span>&nbsp;'
            f'<span style="font-size:0.82rem;font-weight:700;color:{conf_colour};text-transform:capitalize;">{confidence}</span>'
            f'</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

    # Evidence
    evidence = bluf.get("evidence")
    if evidence:
        with st.expander("Evidence", expanded=False):
            st.markdown(
                f'<div style="font-size:0.84rem;color:#c9d1d9;line-height:1.6;">{evidence}</div>',
                unsafe_allow_html=True,
            )

    # Next Steps
    next_steps = bluf.get("next_steps")
    if next_steps:
        _section_label("Next Steps")
        steps = next_steps if isinstance(next_steps, list) else [next_steps]
        for i, step in enumerate(steps, 1):
            st.markdown(
                f'<div style="display:flex;gap:10px;align-items:flex-start;'
                f'font-size:0.84rem;color:#c9d1d9;padding:5px 0;border-bottom:1px solid #1e2a38;">'
                f'<span style="color:#58a6ff;font-weight:700;min-width:18px;">{i}.</span>'
                f'<span>{step}</span>'
                f'</div>',
                unsafe_allow_html=True,
            )


def _render_recommended_actions(incident) -> None:
    """Section 3 — Recommended Actions (display only — no execution)."""
    _section_label("Recommended Actions")
    st.caption("Analyst recommendations only. No action is taken automatically.")

    actions = getattr(incident, "recommended_actions", None) or []

    if not actions:
        st.markdown(
            '<div style="color:#6e7681;font-size:0.82rem;font-style:italic;">No recommended actions available.</div>',
            unsafe_allow_html=True,
        )
        return

    for i, action in enumerate(actions, 1):
        st.markdown(
            f'<div style="display:flex;gap:10px;align-items:flex-start;'
            f'background:#0d1117;border:1px solid #1e2a38;border-left:2px solid #3fb950;'
            f'border-radius:3px;padding:7px 12px;margin-bottom:4px;font-size:0.84rem;color:#c9d1d9;">'
            f'<span style="color:#3fb950;font-weight:700;min-width:18px;">{i}.</span>'
            f'<span>{action}</span>'
            f'</div>',
            unsafe_allow_html=True,
        )


def _render_predicted_techniques(incident) -> None:
    """Section 4 — Predicted Next Techniques."""
    _section_label("Predicted Next Techniques")
    predicted = getattr(incident, "predicted_next_techniques", None) or []

    if not predicted:
        st.markdown(
            '<div style="color:#6e7681;font-size:0.82rem;font-style:italic;">No predictions available.</div>',
            unsafe_allow_html=True,
        )
        return

    _render_tech_chips(predicted)
    st.caption(
        "Predicted based on observed kill-chain progression. "
        "Not confirmed activity."
    )


def _render_analyst_qa(incident) -> None:
    """Section 5 — Analyst Q&A (uses local answer_analyst_question only)."""
    _section_label("Analyst Q&A")

    if not _QA_AVAILABLE:
        st.warning(
            "Analyst Q&A is not currently available — "
            "`reasoning.ai_assistant.answer_analyst_question` could not be loaded."
        )
        return

    inc_id       = getattr(incident, "incident_id", "unknown")
    answer_key   = f"_qa_answer_{inc_id}"
    question_key = f"_qa_question_{inc_id}"

    starter_hints = [
        "Why is this incident critical?",
        "What is the impact of this incident?",
        "Is this a false positive?",
        "What MITRE techniques are involved?",
        "What happened in the attack timeline?",
        "Which assets are affected?",
    ]
    st.caption("Example questions: " + " · ".join(f'"{q}"' for q in starter_hints[:3]))

    question = st.text_input(
        "Ask about this incident",
        key=question_key,
        placeholder="e.g. Why is this incident critical?",
        label_visibility="visible",
    )

    if st.button("Get Answer", key=f"_qa_btn_{inc_id}"):
        q = (question or "").strip()
        if not q:
            st.warning("Please enter a question before clicking Get Answer.")
        else:
            try:
                answer = _qa_fn(incident, q)
                st.session_state[answer_key] = answer
            except Exception as exc:
                st.session_state[answer_key] = (
                    f"An error occurred while answering the question: {exc}"
                )

    if answer_key in st.session_state and st.session_state[answer_key]:
        st.markdown(
            f'<div style="background:#0d1117;border:1px solid #1e2a38;border-left:2px solid #58a6ff;'
            f'border-radius:3px;padding:12px 16px;margin-top:8px;font-size:0.86rem;color:#c9d1d9;line-height:1.6;">'
            f'<div style="font-size:0.65rem;color:#8b949e;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:6px;">Answer</div>'
            f'{st.session_state[answer_key]}'
            f'</div>',
            unsafe_allow_html=True,
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def render_reasoning_panel(incident) -> None:
    """
    Render the AI Reasoning & Reporting panel for a single Incident.

    Safe against None / empty / missing values on every field it reads.
    Does not crash regardless of what the backend has populated.
    Never executes recommended actions.
    Never calls an external API or LLM.
    """
    st.markdown(
        '<div style="font-size:0.72rem;color:#58a6ff;text-transform:uppercase;'
        'letter-spacing:0.12em;margin-bottom:16px;font-weight:700;">AI Reasoning & Reporting</div>',
        unsafe_allow_html=True,
    )

    # Quick header bar — Priority + Risk Score at a glance
    priority   = getattr(incident, "priority", None)
    risk_score = getattr(incident, "risk_score", None)

    if priority or risk_score is not None:
        pri_colour = _pri_hex(priority or "")
        pri_disp   = f"{round(float(risk_score), 1)} / 100" if risk_score is not None else "—"
        st.markdown(
            f'<div style="display:flex;gap:20px;align-items:center;'
            f'background:#0d1117;border:1px solid #1e2a38;border-radius:4px;'
            f'padding:10px 16px;margin-bottom:16px;font-size:0.82rem;">'
            f'<div><span style="color:#8b949e;font-size:0.65rem;text-transform:uppercase;letter-spacing:0.1em;">Priority</span>&nbsp;&nbsp;'
            f'<span style="color:{pri_colour};font-weight:700;">{priority or "—"}</span></div>'
            f'<div><span style="color:#8b949e;font-size:0.65rem;text-transform:uppercase;letter-spacing:0.1em;">Risk Score</span>&nbsp;&nbsp;'
            f'<span style="color:{pri_colour};font-weight:700;">{pri_disp}</span></div>'
            f'</div>',
            unsafe_allow_html=True,
        )

    # Main two-column layout
    col_left, col_right = st.columns([3, 2])

    with col_left:
        _render_ai_explanation(incident)
        st.markdown("<br>", unsafe_allow_html=True)
        _render_bluf_report(incident)

    with col_right:
        _render_recommended_actions(incident)
        st.markdown("<br>", unsafe_allow_html=True)
        _render_predicted_techniques(incident)

    st.markdown("---")
    _render_analyst_qa(incident)
