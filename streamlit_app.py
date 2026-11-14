from __future__ import annotations

import hashlib
import html
import io
import json
from datetime import datetime, timezone

import pandas as pd
import streamlit as st

from engine import (
    METRICS,
    UCI_METRICS,
    MODEL_NOTE,
    MODEL,
    UCI_MODEL,
    analyze_email_headers,
    analyze_message,
    inspect_attachment_name,
    inspect_url,
)


st.set_page_config(
    page_title="FraudBeacon AI | Threat Triage Workspace",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Design system
# ---------------------------------------------------------------------------
CUSTOM_CSS = r"""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800&family=Manrope:wght@500;600;700;800&display=swap');
:root {
  --ink: #14243b;
  --muted: #66758b;
  --muted-2: #8794a7;
  --line: #e5eaf1;
  --surface: #ffffff;
  --canvas: #f4f7fb;
  --navy: #111d32;
  --navy-2: #1a2b45;
  --blue: #356df3;
  --blue-soft: #edf3ff;
  --teal: #12a995;
  --teal-soft: #e9f8f5;
  --amber: #b7791f;
  --amber-soft: #fff6e8;
  --red: #c4495b;
  --red-soft: #fff0f2;
}
html, body, [class*="css"] {
  font-family: 'DM Sans', 'Segoe UI', sans-serif;
  color: var(--ink);
}
.stApp, [data-testid="stAppViewContainer"] { background: var(--canvas); }
[data-testid="stHeader"] { background: rgba(244,247,251,.86); }
[data-testid="stMainBlockContainer"] {
  max-width: 1540px;
  padding-top: 1.45rem;
  padding-bottom: 3.5rem;
}
section[data-testid="stSidebar"] {
  background: linear-gradient(180deg, #101b2e 0%, #14243b 100%);
  border-right: 1px solid rgba(255,255,255,.07);
}
section[data-testid="stSidebar"] > div { background: transparent; }
section[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p,
section[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] span,
section[data-testid="stSidebar"] label,
section[data-testid="stSidebar"] .stCaption,
section[data-testid="stSidebar"] small { color: #d6dfeb !important; }
section[data-testid="stSidebar"] h1,
section[data-testid="stSidebar"] h2,
section[data-testid="stSidebar"] h3 { color: #ffffff !important; }
section[data-testid="stSidebar"] hr { border-color: rgba(255,255,255,.12) !important; }
section[data-testid="stSidebar"] [data-testid="stRadio"] > div { gap: .34rem; }
section[data-testid="stSidebar"] [data-testid="stRadio"] label {
  background: transparent;
  border: 1px solid transparent;
  border-radius: 11px;
  padding: .62rem .72rem;
  transition: background .15s ease, border .15s ease;
}
section[data-testid="stSidebar"] [data-testid="stRadio"] label:hover {
  background: rgba(255,255,255,.075);
  border-color: rgba(255,255,255,.07);
}
section[data-testid="stSidebar"] [data-testid="stRadio"] label:has(input:checked) {
  background: rgba(67,118,235,.20);
  border-color: rgba(112,153,255,.30);
}
section[data-testid="stSidebar"] [data-testid="stRadio"] label p {
  color: #f6f8fc !important;
  font-weight: 650;
}
section[data-testid="stSidebar"] [data-testid="stRadio"] input { accent-color: #80a8ff; }

h1, h2, h3, h4 { color: var(--ink) !important; letter-spacing: -.035em; }
h1 { font-family: 'Manrope', 'DM Sans', sans-serif; font-weight: 800 !important; }
h2, h3 { font-family: 'Manrope', 'DM Sans', sans-serif; font-weight: 750 !important; }
p, li { line-height: 1.65; }
[data-testid="stMarkdownContainer"] p { color: var(--ink); }
[data-testid="stCaptionContainer"] p { color: var(--muted) !important; }

/* Inputs */
.stTextInput input, .stTextArea textarea {
  background: #fff !important;
  color: var(--ink) !important;
  border: 1px solid #dce4ef !important;
  border-radius: 12px !important;
  box-shadow: 0 1px 2px rgba(20,36,59,.03);
  font-size: .98rem !important;
}
.stTextInput input:focus, .stTextArea textarea:focus {
  border-color: #7da0fa !important;
  box-shadow: 0 0 0 3px rgba(53,109,243,.12) !important;
}
.stTextArea textarea { line-height: 1.6 !important; }
[data-baseweb="select"] > div {
  background: #fff !important;
  border: 1px solid #dce4ef !important;
  border-radius: 11px !important;
}
[data-testid="stFileUploader"] section {
  background: #fff;
  border: 1px dashed #b9c8dc;
  border-radius: 14px;
}
.stCheckbox label, .stRadio label { color: var(--ink) !important; }

/* Buttons */
.stButton > button, .stDownloadButton > button {
  min-height: 2.72rem;
  border-radius: 11px;
  border: 1px solid #dce4ef;
  background: #fff;
  color: #273951;
  font-weight: 700;
  box-shadow: 0 1px 2px rgba(20,36,59,.04);
  transition: transform .12s ease, box-shadow .12s ease, border .12s ease;
}
.stButton > button:hover, .stDownloadButton > button:hover {
  border-color: #a9bce0;
  box-shadow: 0 5px 15px rgba(20,36,59,.08);
  transform: translateY(-1px);
  color: #173256;
}
.stButton > button[kind="primary"] {
  color: #fff !important;
  border: 1px solid #356df3 !important;
  background: linear-gradient(135deg, #356df3 0%, #2458d5 100%) !important;
  box-shadow: 0 5px 14px rgba(53,109,243,.18);
}
.stButton > button[kind="primary"]:hover {
  background: linear-gradient(135deg, #285fe6 0%, #1d4fca 100%) !important;
}

/* Cards and layout blocks */
.brand-strip { display:flex; align-items:center; gap:12px; margin:0 0 1.2rem; }
.brand-symbol {
  width:42px; height:42px; display:flex; align-items:center; justify-content:center;
  border-radius:13px; color:#fff; font-size:1.25rem;
  background:linear-gradient(145deg,#477cf4,#1b56d6);
  box-shadow:0 6px 16px rgba(53,109,243,.25);
}
.brand-name { font:800 1.12rem 'Manrope','DM Sans',sans-serif; color:#fff; letter-spacing:-.03em; }
.brand-caption { font-size:.70rem; color:#a8b8cf; letter-spacing:.12em; text-transform:uppercase; font-weight:750; margin-top:1px; }
.sidebar-note { border:1px solid rgba(255,255,255,.11); background:rgba(255,255,255,.055); border-radius:12px; padding:13px 14px; color:#d2dced; font-size:.79rem; line-height:1.6; }
.sidebar-status { display:inline-flex; align-items:center; gap:7px; font-size:.72rem; color:#b7c6d9; letter-spacing:.08em; text-transform:uppercase; font-weight:800; }
.status-dot { display:inline-block; width:7px; height:7px; border-radius:50%; background:#36d6aa; box-shadow:0 0 0 4px rgba(54,214,170,.12); }
.hero {
  position:relative; overflow:hidden; border-radius:22px; padding:27px 31px;
  background:linear-gradient(112deg,#142641 0%,#1a3456 60%,#244b75 100%);
  border:1px solid rgba(33,65,102,.25); box-shadow:0 12px 30px rgba(20,36,59,.09);
  margin-bottom:1.35rem;
}
.hero:after { content:''; position:absolute; width:300px; height:300px; right:-75px; top:-165px; border-radius:50%; border:1px solid rgba(255,255,255,.11); box-shadow:0 0 0 30px rgba(255,255,255,.025),0 0 0 60px rgba(255,255,255,.02); }
.hero-kicker { color:#91b5ff; font-weight:800; font-size:.69rem; letter-spacing:.16em; text-transform:uppercase; }
.hero-title { color:#fff; font:800 clamp(1.8rem,3vw,2.65rem) 'Manrope','DM Sans',sans-serif; margin:.35rem 0 .4rem; letter-spacing:-.05em; }
.hero-text { color:#d4e0f1; font-size:.98rem; max-width:780px; line-height:1.65; }
.hero-meta { display:inline-block; border:1px solid rgba(182,207,255,.24); background:rgba(255,255,255,.07); color:#dbe8fb; border-radius:999px; padding:6px 11px; font-size:.70rem; font-weight:750; margin-top:14px; }
.page-eyebrow { color:#4775d9; font-size:.70rem; font-weight:850; letter-spacing:.14em; text-transform:uppercase; margin-bottom:.35rem; }
.page-description { color:var(--muted); font-size:.96rem; line-height:1.65; margin-top:-.35rem; margin-bottom:1.15rem; }
.surface-card { background:#fff; border:1px solid var(--line); border-radius:17px; padding:19px 21px; box-shadow:0 3px 12px rgba(26,48,78,.035); margin:7px 0 14px; }
.surface-card h3 { margin:.1rem 0 .4rem; }
.soft-card { background:#f9fbfe; border:1px solid #e6edf6; border-radius:14px; padding:15px 17px; margin:8px 0 12px; }
.feature-card { min-height:142px; background:#fff; border:1px solid var(--line); border-radius:16px; padding:19px; box-shadow:0 3px 12px rgba(26,48,78,.035); }
.feature-icon { width:37px; height:37px; display:flex; align-items:center; justify-content:center; border-radius:11px; color:#356df3; background:#edf3ff; font-size:1.1rem; margin-bottom:12px; }
.feature-title { color:var(--ink); font-weight:800; font-size:.96rem; margin-bottom:4px; }
.feature-desc { color:var(--muted); font-size:.82rem; line-height:1.55; }
.metric-tile { background:#fff; border:1px solid var(--line); border-radius:15px; padding:14px 17px; box-shadow:0 2px 8px rgba(26,48,78,.025); }
.metric-label { color:var(--muted); font-size:.74rem; font-weight:700; }
.metric-value { font:800 1.58rem 'Manrope','DM Sans',sans-serif; color:var(--ink); margin-top:3px; }
.metric-sub { color:var(--muted-2); font-size:.73rem; margin-top:1px; }
.pill { display:inline-block; border-radius:999px; padding:5px 9px; font-size:.68rem; font-weight:850; letter-spacing:.04em; text-transform:uppercase; }
.pill-blue { background:#edf3ff; color:#315fc4; }
.pill-green { background:var(--teal-soft); color:#087b6b; }
.pill-amber { background:var(--amber-soft); color:#996116; }
.pill-red { background:var(--red-soft); color:#b43b50; }
.verdict-card { padding:18px 20px; border-radius:16px; border:1px solid; margin:8px 0 14px; }
.verdict-high { background:var(--red-soft); border-color:#f3cbd2; }
.verdict-elevated { background:var(--amber-soft); border-color:#f0ddb8; }
.verdict-low { background:var(--teal-soft); border-color:#c9eae3; }
.verdict-title { font:800 1.08rem 'Manrope','DM Sans',sans-serif; margin-bottom:4px; }
.verdict-high .verdict-title { color:#a9364a; }
.verdict-elevated .verdict-title { color:#956018; }
.verdict-low .verdict-title { color:#087b6b; }
.verdict-desc { color:#596b81; font-size:.87rem; line-height:1.6; }
.signal-card { display:flex; gap:12px; align-items:flex-start; background:#fff; border:1px solid var(--line); border-radius:13px; padding:13px 15px; margin:8px 0; }
.signal-mark { flex:0 0 25px; width:25px; height:25px; display:flex; align-items:center; justify-content:center; color:#315fc4; background:#edf3ff; border-radius:8px; font-weight:900; font-size:.8rem; }
.signal-title { color:var(--ink); font-weight:800; font-size:.88rem; }
.signal-detail { color:var(--muted); font-size:.81rem; line-height:1.55; margin-top:3px; }
.safe-step { display:flex; gap:11px; padding:12px 14px; margin:7px 0; background:#f8fbff; border:1px solid #e7edf5; border-radius:12px; }
.safe-number { flex:0 0 25px; height:25px; display:flex; align-items:center; justify-content:center; border-radius:8px; background:#e9f0ff; color:#315fc4; font-weight:850; font-size:.78rem; }
.safe-text { color:#3e5068; font-size:.85rem; line-height:1.55; }
.notice { border:1px solid #e5eaf2; background:#f8fafd; border-radius:13px; padding:13px 15px; color:#53647a; font-size:.82rem; line-height:1.6; margin:10px 0; }
.notice-warning { background:#fff8ed; border-color:#f1e0c3; color:#805d2c; }
.notice-danger { background:#fff1f3; border-color:#f3d4da; color:#8f3c4b; }
.notice-success { background:#edf9f6; border-color:#cfece4; color:#216f62; }
.empty-state { background:#fff; border:1px dashed #ccd7e5; border-radius:16px; padding:26px 22px; color:var(--muted); text-align:center; }
.empty-icon { font-size:1.55rem; margin-bottom:8px; }
.section-rule { height:1px; background:var(--line); margin:18px 0; }
.kv-label { color:var(--muted); font-size:.74rem; font-weight:700; margin-bottom:3px; }
.kv-value { color:var(--ink); font-size:.9rem; font-weight:700; overflow-wrap:anywhere; }
.footer-line { border-top:1px solid #e4eaf2; margin-top:2rem; padding-top:1rem; color:#8a97a8; font-size:.74rem; line-height:1.6; }
[data-testid="stMetric"] { background:#fff; border:1px solid var(--line); border-radius:14px; padding:13px 15px; box-shadow:0 2px 8px rgba(26,48,78,.025); }
[data-testid="stMetricLabel"] { color:var(--muted) !important; font-weight:650; }
[data-testid="stMetricValue"] { color:var(--ink) !important; font-family:'Manrope','DM Sans',sans-serif; font-weight:800; }
[data-testid="stTabs"] button { font-weight:750; color:#60718a; }
[data-testid="stTabs"] button[aria-selected="true"] { color:#2f62dc; }
[data-testid="stDataFrame"] { border:1px solid var(--line); border-radius:12px; overflow:hidden; }
hr { border-color:var(--line) !important; }
#MainMenu, footer { visibility:hidden; }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Session state and shared helpers
# ---------------------------------------------------------------------------
PAGES = [
    "Overview",
    "Message scanner",
    "URL inspector",
    "Email analysis",
    "Batch triage",
    "Learning lab",
    "Research & model",
]

for key, default in {
    "nav_choice": "Overview",
    "latest_message_result": None,
    "latest_message_fingerprint": None,
    "latest_url_result": None,
    "latest_url_fingerprint": None,
    "latest_email_result": None,
    "latest_email_fingerprint": None,
    "latest_attachment_result": None,
    "latest_attachment_fingerprint": None,
    "batch_result": None,
    "scan_history": [],
    "scan_count": 0,
    "quiz_result": None,
    "message_text": "",
    "url_input": "",
    "email_headers": "",
    "attachment_name": "",
}.items():
    if key not in st.session_state:
        st.session_state[key] = default


def go_to(page: str) -> None:
    st.session_state.nav_choice = page


def clear_history() -> None:
    st.session_state.scan_history = []
    st.session_state.scan_count = 0


def escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def page_heading(eyebrow: str, title: str, description: str) -> None:
    st.markdown(
        f'<div class="page-eyebrow">{escape(eyebrow)}</div>'
        f'<h1 style="font-size:2.05rem;margin:0 0 .55rem;">{escape(title)}</h1>'
        f'<div class="page-description">{escape(description)}</div>',
        unsafe_allow_html=True,
    )


def notice(text: str, kind: str = "") -> None:
    cls = "notice" + (f" notice-{kind}" if kind else "")
    st.markdown(f'<div class="{cls}">{escape(text)}</div>', unsafe_allow_html=True)


def feature_card(icon: str, title: str, description: str) -> None:
    st.markdown(
        f'<div class="feature-card"><div class="feature-icon">{icon}</div>'
        f'<div class="feature-title">{escape(title)}</div>'
        f'<div class="feature-desc">{escape(description)}</div></div>',
        unsafe_allow_html=True,
    )


def metric_tile(label: str, value: object, sub: str = "") -> None:
    st.markdown(
        f'<div class="metric-tile"><div class="metric-label">{escape(label)}</div>'
        f'<div class="metric-value">{escape(value)}</div>'
        f'<div class="metric-sub">{escape(sub)}</div></div>',
        unsafe_allow_html=True,
    )


def show_signal(title: str, detail: str, points: int | None = None, icon: str = "i") -> None:
    suffix = f'<span style="color:#7d8da2;font-size:.72rem;font-weight:700;margin-left:7px">+{points}</span>' if points is not None else ""
    st.markdown(
        f'<div class="signal-card"><div class="signal-mark">{escape(icon)}</div>'
        f'<div><div class="signal-title">{escape(title)}{suffix}</div>'
        f'<div class="signal-detail">{escape(detail)}</div></div></div>',
        unsafe_allow_html=True,
    )


def show_safe_steps(steps: list[str]) -> None:
    for index, item in enumerate(steps, start=1):
        st.markdown(
            f'<div class="safe-step"><div class="safe-number">{index}</div>'
            f'<div class="safe-text">{escape(item)}</div></div>',
            unsafe_allow_html=True,
        )


def add_history(result: dict, text: str) -> None:
    record = {
        "time": datetime.now().astimezone().strftime("%H:%M:%S"),
        "verdict": result["verdict"],
        "risk_score": result["indicators"]["score"],
        "urls": result["url_count"],
        "language": result["language"],
        "characters": len(text),
    }
    st.session_state.scan_history.insert(0, record)
    st.session_state.scan_history = st.session_state.scan_history[:12]
    st.session_state.scan_count += 1


def language_label(code: str) -> str:
    return {
        "arabic": "Arabic script",
        "mixed": "Mixed Arabic / Latin",
        "french": "French-like Latin",
        "english_or_other_latin": "Latin script (English or another language)",
        "unknown": "Undetermined",
    }.get(code, code.replace("_", " ").title())


def verdict_copy(verdict: str) -> tuple[str, str, str]:
    if verdict == "high":
        return (
            "verdict-high",
            "High risk signals",
            "Several strong warning indicators were found. Do not interact until you verify the request through an independent channel.",
        )
    if verdict == "elevated":
        return (
            "verdict-elevated",
            "Suspicious — review carefully",
            "Some warning indicators were found. Pause and verify the sender, destination and request before taking action.",
        )
    return (
        "verdict-low",
        "No strong indicators found",
        "The current checks found few obvious warning indicators. This does not prove the message is legitimate or safe.",
    )


def render_message_result(result: dict, scanned_text: str) -> None:
    verdict_class, verdict_title, verdict_desc = verdict_copy(result["verdict"])
    score = int(result["indicators"]["score"])

    st.markdown(
        f'<div class="verdict-card {verdict_class}"><div class="verdict-title">{verdict_title}</div>'
        f'<div class="verdict-desc">{verdict_desc}</div></div>',
        unsafe_allow_html=True,
    )

    cols = st.columns(3)
    cols[0].metric("Rule-based risk indicators", f"{score}/100")
    cols[1].metric("Detected language pattern", language_label(result["language"]))
    cols[2].metric("URLs found", result["url_count"])
    st.progress(score / 100)
    st.caption("Rule-based indicator score — not a probability of fraud")

    if result.get("ml_score") is not None:
        st.markdown("#### Machine-learning pattern signal")
        model_cols = st.columns([1, 2])
        model_cols[0].metric("Uncalibrated model score", f'{result["ml_score"] * 100:.1f}/100')
        if result.get("ml_source") == "public_uci_english_spam":
            model_note = "This is a separate English spam/ham model trained from UCI data if you have run the optional trainer. Spam includes unwanted messages beyond phishing. Its score is not a probability of fraud."
        else:
            model_note = MODEL_NOTE
        model_cols[1].markdown(
            f'<div class="notice">{escape(model_note)}</div>',
            unsafe_allow_html=True,
        )

    st.markdown("#### Why the scanner raised a signal")
    items = result["indicators"]["items"]
    if items:
        for item in items:
            show_signal(item["title_en"], item["detail_en"], item.get("points"), "!")
    else:
        notice("No specific rule-based indicators were triggered. Check the sender, context and destination independently.", "success")

    if result["indicators"]["urls"]:
        st.markdown("#### Links found in the message")
        for idx, url_item in enumerate(result["indicators"]["urls"], start=1):
            with st.expander(f'Link {idx} · {url_item["verdict"].upper()} · {url_item["score"]}/100'):
                st.code(url_item["url"], language="text")
                st.write(f'Host: `{url_item["host"]}`  ·  Scheme: `{url_item["scheme"]}`')
                for title, detail in url_item["signals"]:
                    show_signal(title, detail, icon="↗")

    st.markdown("#### Safer next steps")
    show_safe_steps([
        "Do not click unexpected links or open unexpected attachments.",
        "Never share OTPs, passwords, PINs, recovery codes or card security codes.",
        "Open the official app or type a known website address yourself instead of using the message link.",
        "Contact the organization through a phone number or channel you already trust.",
    ])

    report = {
        "report_type": "FraudBeacon AI message triage",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "input_sha256_prefix": hashlib.sha256(scanned_text.encode("utf-8", errors="replace")).hexdigest()[:16],
        "input_character_count": len(scanned_text),
        "result": result,
        "note": "The original message text is intentionally excluded from this report export.",
    }
    st.download_button(
        "Download analysis report (JSON)",
        data=json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8"),
        file_name="fraudbeacon_message_report.json",
        mime="application/json",
        use_container_width=True,
    )
    st.caption("The exported report excludes the original message text. It contains analysis findings and a short hash reference only.")


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown(
        '<div class="brand-strip"><div class="brand-symbol">🛡</div><div>'
        '<div class="brand-name">FraudBeacon AI</div><div class="brand-caption">Digital threat triage</div>'
        '</div></div>',
        unsafe_allow_html=True,
    )
    st.markdown('<div class="sidebar-status"><span class="status-dot"></span> Local analysis workspace</div>', unsafe_allow_html=True)
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("<div style='font-size:.68rem;letter-spacing:.13em;font-weight:850;color:#8fa5c2;margin:5px 0 9px'>WORKSPACE</div>", unsafe_allow_html=True)

    page_icons = {
        "Overview": "⌂  Overview",
        "Message scanner": "✉  Message scanner",
        "URL inspector": "↗  URL inspector",
        "Email analysis": "▤  Email analysis",
        "Batch triage": "▦  Batch triage",
        "Learning lab": "✦  Learning lab",
        "Research & model": "◈  Research & model",
    }
    page_key = st.radio(
        "Workspace navigation",
        options=PAGES,
        format_func=lambda p: page_icons[p],
        key="nav_choice",
        label_visibility="collapsed",
    )
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown(
        '<div class="sidebar-note"><b style="color:#fff">Privacy & safe use</b><br>'
        'Use synthetic examples in public demos. Never paste passwords, OTPs, PINs, card details or private conversations. '
        'A low-risk result is not proof of safety.</div>',
        unsafe_allow_html=True,
    )
    st.markdown("<br>", unsafe_allow_html=True)
    st.caption("Research MVP · English interface · Multilingual message input")


# ---------------------------------------------------------------------------
# Main masthead
# ---------------------------------------------------------------------------
st.markdown(
    '<div class="hero"><div class="hero-kicker">AI + FINANCE · CYBER SAFETY</div>'
    '<div class="hero-title">FraudBeacon AI</div>'
    '<div class="hero-text">Understand suspicious digital messages before they become costly mistakes. '
    'Review messages, URLs, email headers and attachment names in one explainable workspace.</div>'
    '<div class="hero-meta">INTERNATIONAL HACKATHON EDITION &nbsp;·&nbsp; RESEARCH MVP</div></div>',
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------
if page_key == "Overview":
    page_heading(
        "Workspace overview",
        "Your first line of digital caution.",
        "A practical triage workspace for individuals, students and small teams reviewing suspicious messages and links.",
    )

    history = st.session_state.scan_history
    total = st.session_state.scan_count
    high_count = sum(1 for row in history if row["verdict"] == "high")
    review_count = sum(1 for row in history if row["verdict"] == "elevated")
    low_count = sum(1 for row in history if row["verdict"] == "low")
    stats = st.columns(4)
    with stats[0]:
        metric_tile("Message scans this session", total, "Recent session activity")
    with stats[1]:
        metric_tile("High-risk signals", high_count, "Rule-based verdicts")
    with stats[2]:
        metric_tile("Needs review", review_count, "Pause and verify")
    with stats[3]:
        metric_tile("No strong signals", low_count, "Not a safety guarantee")

    st.markdown("### Explore the workspace")
    row1 = st.columns(3, gap="medium")
    with row1[0]:
        feature_card("✉", "Message scanner", "Review SMS, email bodies, payment alerts and social messages with explainable warning signals.")
        st.button("Open message scanner", key="open_msg", use_container_width=True, on_click=go_to, args=("Message scanner",))
    with row1[1]:
        feature_card("↗", "URL inspector", "Review visible link structure without opening the destination or sending a request.")
        st.button("Inspect a URL", key="open_url", use_container_width=True, on_click=go_to, args=("URL inspector",))
    with row1[2]:
        feature_card("▤", "Email analysis", "Check sender and reply-to mismatches, authentication results and risky attachment names.")
        st.button("Review email evidence", key="open_email", use_container_width=True, on_click=go_to, args=("Email analysis",))
    row2 = st.columns(3, gap="medium")
    with row2[0]:
        feature_card("▦", "Batch triage", "Analyze a CSV of up to 200 message samples and export a findings report.")
        st.button("Open batch triage", key="open_batch", use_container_width=True, on_click=go_to, args=("Batch triage",))
    with row2[1]:
        feature_card("✦", "Learning lab", "Practice identifying social-engineering tactics through short realistic scenarios.")
        st.button("Start learning", key="open_learn", use_container_width=True, on_click=go_to, args=("Learning lab",))
    with row2[2]:
        feature_card("◈", "Research & model", "Explore the model, evaluation results, limitations and research roadmap transparently.")
        st.button("View research", key="open_research", use_container_width=True, on_click=go_to, args=("Research & model",))

    st.markdown("### Recent message scans")
    if history:
        history_df = pd.DataFrame(history)[["time", "verdict", "risk_score", "urls", "language", "characters"]]
        history_df.columns = ["Time", "Verdict", "Rule score", "URLs", "Language pattern", "Characters"]
        st.dataframe(history_df, use_container_width=True, hide_index=True)
        st.caption("This history exists only in the current browser session and stores summary metadata, not the original message text.")
        st.button("Clear session history", on_click=clear_history)
    else:
        st.markdown('<div class="empty-state"><div class="empty-icon">⌁</div><b>No scans yet</b><br>Run a message analysis and your recent session summaries will appear here.</div>', unsafe_allow_html=True)

    st.markdown("### A simple way to use FraudBeacon")
    show_safe_steps([
        "Paste a message or inspect a URL. Remove personal information first.",
        "Review the signals and their explanations instead of relying only on the verdict.",
        "Verify important requests using an independent, trusted channel before acting.",
    ])
    notice("FraudBeacon is an awareness and triage aid. It does not block attacks, scan file contents, connect to inboxes or confirm live website reputation.", "warning")


# ---------------------------------------------------------------------------
# Message scanner
# ---------------------------------------------------------------------------
elif page_key == "Message scanner":
    page_heading(
        "Message intelligence",
        "Scan a suspicious message.",
        "Review SMS, email text, chat messages, social DMs, payment alerts and delivery notices. The interface is English; the underlying rules also recognize selected Arabic and French warning patterns.",
    )
    samples = {
        "Account suspension · credential request": "Your account will be suspended in 15 minutes. Verify your password and one-time code at https://secure-account-check.example/login to restore access.",
        "Delivery fee · suspicious payment link": "Your parcel is on hold. Pay a small customs fee at https://parcel-release.example/fee within 2 hours or it will be returned.",
        "Brand impersonation · Microsoft": "Microsoft Security: unusual sign-in detected. Reply with your recovery code so our agent can protect your account.",
        "Payroll update · credential harvesting": "Your payroll deposit is on hold. Confirm your bank login and password at https://payroll-security.example/login within 20 minutes to release your payment.",
        "Legitimate · ordinary meeting update": "Hi, the meeting has moved to 3:30 pm. Please bring the printed agenda. Thanks!",
        "Legitimate · security awareness advice": "Never share your OTP or password with anyone. Open the official app yourself to verify unexpected alerts.",
    }

    left, right = st.columns([1.06, .94], gap="large")
    with left:
        st.markdown("#### Message input")
        selected_sample = st.selectbox("Load a demonstration scenario", ["Choose a scenario"] + list(samples.keys()), key="sample_picker")
        b1, b2 = st.columns([1, 1])
        with b1:
            if st.button("Load example", use_container_width=True):
                if selected_sample in samples:
                    st.session_state.message_text = samples[selected_sample]
                    st.session_state.latest_message_result = None
                    st.session_state.latest_message_fingerprint = None
                    st.rerun()
        with b2:
            if st.button("Clear input", use_container_width=True):
                st.session_state.message_text = ""
                st.session_state.latest_message_result = None
                st.session_state.latest_message_fingerprint = None
                st.rerun()
        st.text_area(
            "Message content",
            key="message_text",
            height=265,
            placeholder="Paste the suspicious message here...",
            help="Remove names, phone numbers, account IDs, passwords and other personal data first.",
        )
        st.caption(f"{len(st.session_state.message_text)} characters · Up to 10 URLs are extracted for review")
        scan_clicked = st.button("Analyze message", type="primary", use_container_width=True)
        notice("Privacy reminder: if you deploy this app publicly, submitted text is processed by the hosting server. Use synthetic examples in judge demos.", "warning")

        if scan_clicked:
            try:
                text = st.session_state.message_text
                result = analyze_message(text)
                st.session_state.latest_message_result = result
                st.session_state.latest_message_fingerprint = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
                add_history(result, text)
                st.toast("Analysis complete", icon="✅")
            except ValueError as exc:
                st.warning(str(exc))

    with right:
        st.markdown("#### Analysis report")
        result = st.session_state.latest_message_result
        current_fingerprint = hashlib.sha256(st.session_state.message_text.encode("utf-8", errors="replace")).hexdigest() if st.session_state.message_text else None
        if result and current_fingerprint == st.session_state.latest_message_fingerprint:
            render_message_result(result, st.session_state.message_text)
        elif result:
            notice("The input has changed since the last scan. Run the analysis again to refresh this report.", "warning")
            st.markdown('<div class="empty-state"><div class="empty-icon">↻</div><b>Waiting for a fresh scan</b><br>Run Analyze message to update the report.</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="empty-state"><div class="empty-icon">⌕</div><b>Your report will appear here</b><br>Load a sample or paste a message, then select Analyze message.</div>', unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# URL inspector
# ---------------------------------------------------------------------------
elif page_key == "URL inspector":
    page_heading(
        "Link intelligence",
        "Inspect a URL without opening it.",
        "Review visible URL structure for common warning signs. This is an offline structural check, not a live reputation or malware service.",
    )
    left, right = st.columns([1, 1], gap="large")
    with left:
        st.markdown("#### URL to inspect")
        url_value = st.text_input("Paste a full URL or domain", key="url_input", placeholder="https://example.com/account/verify")
        inspect_clicked = st.button("Inspect URL", type="primary", use_container_width=True)
        st.markdown("<div class='section-rule'></div>", unsafe_allow_html=True)
        st.markdown("**Safe demonstration URLs**")
        st.code(
            "https://paypal-account-security.example/login\nhttp://198.51.100.25/verify\nhttps://bit.ly/example",
            language="text",
        )
        notice("The scanner does not visit the URL, resolve DNS, follow redirects, download content or confirm whether a website is malicious. HTTPS alone does not prove legitimacy.", "warning")
        if inspect_clicked:
            try:
                st.session_state.latest_url_result = inspect_url(url_value, "en")
                st.session_state.latest_url_fingerprint = hashlib.sha256(url_value.strip().encode("utf-8", errors="replace")).hexdigest()
                st.toast("URL inspection complete", icon="✅")
            except ValueError as exc:
                st.warning(str(exc))

    with right:
        st.markdown("#### Inspection report")
        r = st.session_state.latest_url_result
        current_url_fingerprint = hashlib.sha256(url_value.strip().encode("utf-8", errors="replace")).hexdigest() if url_value.strip() else None
        if r and current_url_fingerprint == st.session_state.latest_url_fingerprint:
            verdict = r["verdict"]
            if verdict == "high":
                pill_class, verdict_text = "pill-red", "High structural concern"
            elif verdict == "medium":
                pill_class, verdict_text = "pill-amber", "Review recommended"
            else:
                pill_class, verdict_text = "pill-green", "Few structural warnings"
            st.markdown(
                f'<div class="surface-card"><span class="pill {pill_class}">{verdict_text}</span>'
                f'<div style="font:800 2.15rem Manrope,sans-serif;color:#14243b;margin-top:9px">{r["score"]}/100</div>'
                f'<div class="metric-label">Structural warning score</div><div class="section-rule"></div>'
                f'<div class="kv-label">Host</div><div class="kv-value">{escape(r["host"])}</div>'
                f'<div class="kv-label" style="margin-top:10px">Scheme</div><div class="kv-value">{escape(r["scheme"])}</div>'
                f'<div class="kv-label" style="margin-top:10px">Submitted URL</div><div class="kv-value">{escape(r["url"])}</div></div>',
                unsafe_allow_html=True,
            )
            st.progress(r["score"] / 100)
            st.caption("Structural warning score")
            st.markdown("#### Detected signals")
            if r["signals"]:
                for title, detail in r["signals"]:
                    show_signal(title, detail, icon="!")
            else:
                notice("No structural warning was detected by the current checks. That is not a guarantee that the website is safe.", "success")
        elif r:
            notice("The URL input has changed since the last inspection. Run Inspect URL again to refresh the report.", "warning")
        else:
            st.markdown('<div class="empty-state"><div class="empty-icon">↗</div><b>No URL inspected yet</b><br>Paste a URL and select Inspect URL.</div>', unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Email analysis
# ---------------------------------------------------------------------------
elif page_key == "Email analysis":
    page_heading(
        "Email and attachment review",
        "Check the details behind an email.",
        "Review raw email headers and attachment filenames. These checks help prioritize manual review; they do not authenticate or scan a complete message or file.",
    )
    header_tab, attachment_tab = st.tabs(["Email header review", "Attachment filename check"])

    with header_tab:
        left, right = st.columns([1.05, .95], gap="large")
        with left:
            st.markdown("#### Paste raw email headers")
            st.caption("In most mail clients, use the message details or 'Show original' option. Paste headers only; remove personal addresses where possible.")
            headers = st.text_area(
                "Raw email headers",
                key="email_headers",
                height=270,
                placeholder=(
                    "From: Security Team <notice@example.com>\n"
                    "Reply-To: support@different-domain.example\n"
                    "Return-Path: bounce@mailer.example\n"
                    "Authentication-Results: mx.example; spf=fail; dkim=pass; dmarc=fail"
                ),
            )
            run_headers = st.button("Review email headers", type="primary", use_container_width=True)
            if run_headers:
                st.session_state.latest_email_result = analyze_email_headers(headers)
                st.session_state.latest_email_fingerprint = hashlib.sha256(headers.encode("utf-8", errors="replace")).hexdigest()
        with right:
            st.markdown("#### Header findings")
            result = st.session_state.latest_email_result
            email_fingerprint = hashlib.sha256(headers.encode("utf-8", errors="replace")).hexdigest()
            if result and email_fingerprint == st.session_state.latest_email_fingerprint:
                c1, c2 = st.columns(2)
                c1.metric("Header warning points", f'{result["score"]}/100')
                c2.metric("Findings", len(result["findings"]))
                st.progress(result["score"] / 100)
                st.caption("Header warning points — not a probability")
                if result["findings"]:
                    for title, detail in result["findings"]:
                        show_signal(title, detail, icon="!")
                else:
                    notice("No header warning was identified by the current checks. Review the sender and content context manually.", "success")
                st.markdown("**Parsed fields**")
                parsed = result["parsed"]
                parsed_df = pd.DataFrame([{"Field": k.replace("_", " ").title(), "Value": v or "Not found"} for k, v in parsed.items()])
                st.dataframe(parsed_df, use_container_width=True, hide_index=True)
            elif result:
                notice("The header input has changed since the last review. Run Review email headers again to refresh the findings.", "warning")
            else:
                st.markdown('<div class="empty-state"><div class="empty-icon">▤</div><b>No headers reviewed yet</b><br>Paste raw headers to see the findings.</div>', unsafe_allow_html=True)
        notice("SPF, DKIM and DMARC results help assess mail authentication. A pass does not prove the email content is safe, and a failure may require context from a mail administrator.", "warning")

    with attachment_tab:
        left, right = st.columns([1, 1], gap="large")
        with left:
            st.markdown("#### Check an attachment name")
            filename = st.text_input("Filename", key="attachment_name", placeholder="invoice.pdf.exe")
            check_name = st.button("Check filename", type="primary", use_container_width=True)
            if check_name:
                try:
                    st.session_state.latest_attachment_result = inspect_attachment_name(filename)
                    st.session_state.latest_attachment_fingerprint = hashlib.sha256(filename.strip().encode("utf-8", errors="replace")).hexdigest()
                except ValueError as exc:
                    st.warning(str(exc))
        with right:
            st.markdown("#### Filename findings")
            result = st.session_state.latest_attachment_result
            attachment_fingerprint = hashlib.sha256(st.session_state.attachment_name.strip().encode("utf-8", errors="replace")).hexdigest() if st.session_state.attachment_name.strip() else None
            if result and attachment_fingerprint == st.session_state.latest_attachment_fingerprint:
                a, b = st.columns(2)
                a.metric("Filename warning score", f'{result["score"]}/100')
                b.metric("Extensions detected", len(result["extensions"]))
                st.code(result["filename"], language="text")
                for title, detail in result["findings"]:
                    show_signal(title, detail, icon="!")
            elif result:
                notice("The filename has changed since the last check. Run Check filename again to refresh the findings.", "warning")
            else:
                st.markdown('<div class="empty-state"><div class="empty-icon">⌁</div><b>No filename checked yet</b><br>Enter a filename to review its visible extension.</div>', unsafe_allow_html=True)
        notice("Filename-only inspection. The app does not upload, open, execute or scan file contents. Use reputable security software and an isolated environment for actual file analysis.", "warning")


# ---------------------------------------------------------------------------
# Batch triage
# ---------------------------------------------------------------------------
elif page_key == "Batch triage":
    page_heading(
        "Multi-message review",
        "Triage a small message dataset.",
        "Upload a CSV with a message, text, body, sms, email or content column. The demo processes up to 200 rows per run.",
    )
    demo_csv = pd.DataFrame(
        {
            "message": [
                "Your account is locked. Enter your password and OTP at https://account-check.example now.",
                "Hi, the project meeting has moved to 3:30 pm. See you there.",
                "Votre compte bancaire sera bloqué. Confirmez votre mot de passe sur https://banque-verification.example.",
                "Never share your one-time code with anyone. Open the official app to review alerts.",
            ]
        }
    )
    st.download_button(
        "Download sample CSV",
        data=demo_csv.to_csv(index=False).encode("utf-8-sig"),
        file_name="fraudbeacon_sample_messages.csv",
        mime="text/csv",
    )
    uploaded = st.file_uploader("Upload message CSV", type=["csv"], help="Use synthetic or consented data. Remove personal information before uploading.")
    if uploaded:
        if uploaded.size > 8 * 1024 * 1024:
            st.error("The CSV is larger than the 8 MB demo limit. Please use a smaller file.")
        else:
            try:
                dataframe = pd.read_csv(uploaded)
                text_columns = [c for c in dataframe.columns if str(c).strip().lower() in {"message", "text", "body", "sms", "email", "content"}]
                if not text_columns:
                    text_columns = [c for c in dataframe.columns if dataframe[c].dtype == object]
                if not text_columns:
                    st.error("No text column found. Add a column named message, text, body, sms, email or content.")
                else:
                    chosen_column = st.selectbox("Message text column", text_columns)
                    st.markdown("#### Data preview")
                    st.dataframe(dataframe[[chosen_column]].head(5), use_container_width=True, hide_index=True)
                    if len(dataframe) > 200:
                        notice(f"Your file contains {len(dataframe)} rows. Only the first 200 will be analyzed in this demo.", "warning")
                    if st.button("Analyze first 200 messages", type="primary"):
                        output_rows = []
                        values = dataframe[chosen_column].head(200).fillna("").astype(str)
                        progress = st.progress(0)
                        st.caption("Analyzing messages...")
                        for index, value in enumerate(values, start=1):
                            if len(value.strip()) < 4:
                                output_rows.append({"row": index, "verdict": "not_analyzed", "rule_score": None, "ml_signal": None, "url_count": 0})
                            else:
                                analysis = analyze_message(value)
                                output_rows.append(
                                    {
                                        "row": index,
                                        "verdict": analysis["verdict"],
                                        "rule_score": analysis["indicators"]["score"],
                                        "ml_signal": round(analysis["ml_score"] * 100, 1) if analysis["ml_score"] is not None else None,
                                        "url_count": analysis["url_count"],
                                    }
                                )
                            progress.progress(index / max(len(values), 1))
                        st.session_state.batch_result = pd.DataFrame(output_rows)
                        st.toast("Batch analysis complete", icon="✅")
            except Exception as exc:
                st.error(f"Could not read this CSV: {exc}")

    if st.session_state.batch_result is not None:
        output = st.session_state.batch_result
        st.markdown("### Batch summary")
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Rows processed", len(output))
        c2.metric("High risk", int((output["verdict"] == "high").sum()))
        c3.metric("Needs review", int((output["verdict"] == "elevated").sum()))
        c4.metric("Low indicator score", int((output["verdict"] == "low").sum()))
        st.dataframe(output, use_container_width=True, hide_index=True)
        report_csv = output.to_csv(index=False).encode("utf-8-sig")
        st.download_button(
            "Download batch findings (CSV)",
            data=report_csv,
            file_name="fraudbeacon_batch_report.csv",
            mime="text/csv",
            use_container_width=True,
        )
        notice("The exported batch report contains row numbers and analysis summaries only. Original message text is not copied into the report.", "success")
    else:
        st.markdown('<div class="empty-state"><div class="empty-icon">▦</div><b>No batch report yet</b><br>Upload a CSV and run the analysis to see a summary.</div>', unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Learning lab
# ---------------------------------------------------------------------------
elif page_key == "Learning lab":
    page_heading(
        "Security awareness",
        "Practice the pause-and-verify habit.",
        "Short scenarios help build safer instincts around account alerts, payments, delivery messages and remote access requests.",
    )
    questions = [
        {
            "q": "A message says your account will close in 10 minutes unless you enter your one-time code through a link. What is the safest response?",
            "options": ["Enter the code quickly", "Open the official app independently and verify", "Reply and ask for more time"],
            "answer": 1,
            "why": "A one-time code is an authentication secret. Do not reveal it through an unsolicited link. Open the official app or website independently.",
        },
        {
            "q": "An email passes SPF, DKIM and DMARC. Does that prove the message content is safe?",
            "options": ["Yes, authentication guarantees safety", "No, authentication does not prove the request is safe", "Only if the email looks professional"],
            "answer": 1,
            "why": "These checks help authenticate sending infrastructure and alignment. They do not guarantee that the sender account is uncompromised or that the request is legitimate.",
        },
        {
            "q": "A delivery message contains a shortened link and asks for a small customs fee. What should you do?",
            "options": ["Pay quickly to avoid losing the parcel", "Open the short link in a private window", "Check the shipment using the courier's official site or app"],
            "answer": 2,
            "why": "Use a known official channel and enter the tracking number yourself. A shortened link hides its final destination.",
        },
        {
            "q": "An unexpected caller asks you to install a remote-support app and share the access code. What is the main risk?",
            "options": ["They may view or control your device", "It only improves connection speed", "There is no meaningful risk"],
            "answer": 0,
            "why": "Remote-support tools can expose your screen or allow device control. Do not install them at the request of an unsolicited caller.",
        },
        {
            "q": "A login page uses HTTPS and shows a padlock. What does that tell you?",
            "options": ["The website is definitely legitimate", "The connection is encrypted, but the site may still be fraudulent", "The website has no security issues"],
            "answer": 1,
            "why": "HTTPS protects the connection to the site. It does not prove who owns the domain or whether the requested action is safe.",
        },
    ]

    if "quiz_answers" not in st.session_state:
        st.session_state.quiz_answers = [0] * len(questions)
    with st.form("awareness_quiz"):
        chosen_answers = []
        for index, item in enumerate(questions):
            st.markdown(
                f'<div class="surface-card"><div class="page-eyebrow">SCENARIO {index + 1:02d}</div>'
                f'<div style="font-size:1rem;font-weight:800;color:#14243b;line-height:1.5">{escape(item["q"])}</div></div>',
                unsafe_allow_html=True,
            )
            selected = st.radio(
                f"Answer scenario {index + 1}",
                options=list(range(3)),
                format_func=lambda value, opts=item["options"]: opts[value],
                key=f"quiz_answer_{index}",
                label_visibility="collapsed",
            )
            chosen_answers.append(selected)
        submitted = st.form_submit_button("Check my answers", type="primary", use_container_width=True)
    if submitted:
        correct = sum(1 for idx, answer in enumerate(chosen_answers) if answer == questions[idx]["answer"])
        st.session_state.quiz_result = {
            "score": correct,
            "answers": chosen_answers,
            "questions": questions,
        }
    if st.session_state.quiz_result:
        result = st.session_state.quiz_result
        score = result["score"]
        st.markdown("### Your learning result")
        st.success(f"You answered {score} out of {len(questions)} correctly.")
        st.progress(score / len(questions))
        st.caption(f"{int(score / len(questions) * 100)}% correct")
        for idx, item in enumerate(questions):
            selected = result["answers"][idx]
            if selected == item["answer"]:
                st.markdown(f"✅ **Scenario {idx + 1}: Correct**")
            else:
                st.markdown(f"⚠️ **Scenario {idx + 1}: Review the safer choice**")
                st.caption(f"Safer answer: {item['options'][item['answer']]}")
            st.caption(item["why"])

    st.markdown("### The 30-second verification routine")
    show_safe_steps([
        "Pause: urgency is a pressure tactic. Take a breath before reacting.",
        "Inspect the sender: check the full address or number, not only the display name.",
        "Separate the channel: open the official app or type the known website yourself.",
        "Protect secrets: never give away OTPs, passwords, PINs or recovery codes.",
        "Report and recover: use the provider's reporting channel and contact your bank if money or credentials are at risk.",
    ])


# ---------------------------------------------------------------------------
# Research and model transparency
# ---------------------------------------------------------------------------
elif page_key == "Research & model":
    page_heading(
        "Technical transparency",
        "What the model does — and what it does not.",
        "The research page separates explainable rules from the text model and reports the current prototype evaluation honestly.",
    )
    metrics = METRICS or {}
    model_metrics = metrics.get("model", {})
    baseline_metrics = metrics.get("baseline", {})
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Synthetic examples", metrics.get("dataset_rows", "—"))
    c2.metric("Training examples", metrics.get("train_rows", "—"))
    c3.metric("Held-out examples", metrics.get("test_rows", "—"))
    c4.metric("Model accuracy", f'{model_metrics.get("accuracy", 0) * 100:.1f}%')

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Scam precision", f'{model_metrics.get("precision_scam", 0) * 100:.1f}%')
    m2.metric("Scam recall", f'{model_metrics.get("recall_scam", 0) * 100:.1f}%')
    m3.metric("Scam F1", f'{model_metrics.get("f1_scam", 0) * 100:.1f}%')
    m4.metric("Majority baseline", f'{baseline_metrics.get("accuracy", 0) * 100:.1f}%')

    notice(
        "Important evaluation limit: these values come from a grouped holdout of 136 AI-assisted synthetic messages (100 train / 36 test). They are not real-world, international or field-performance results.",
        "warning",
    )
    status_left, status_right = st.columns(2)
    if MODEL is not None:
        status_left.success("Bundled text-classifier artifact loaded")
    else:
        status_left.error("Bundled text-classifier artifact not loaded")
    if UCI_MODEL is not None:
        status_right.success("Optional English UCI model loaded")
    else:
        status_right.info("Optional English UCI model not installed")

    st.markdown("### Confusion matrix")
    matrix = metrics.get("confusion_matrix", [[0, 0], [0, 0]])
    matrix_df = pd.DataFrame(
        matrix,
        index=["Actual: legitimate", "Actual: suspicious"],
        columns=["Predicted: legitimate", "Predicted: suspicious"],
    )
    st.dataframe(matrix_df, use_container_width=True)
    st.caption("The current held-out test includes 2 false alarms and 4 missed suspicious examples. Those errors must remain visible in the project write-up.")

    st.markdown("### Model components")
    component_cols = st.columns(3)
    with component_cols[0]:
        feature_card("⚖", "Explainable rules", "Primary decision support from credential requests, urgency, impersonation, money pressure, threats and URL structure.")
    with component_cols[1]:
        feature_card("✳", "Text classifier", "Word and character TF-IDF features with Logistic Regression. Its output is an uncalibrated pattern signal.")
    with component_cols[2]:
        feature_card("⌁", "Offline inspectors", "URL structure, email headers and filename checks run locally in the app without contacting the destination URL.")

    st.markdown("### Optional English public-data baseline")
    if UCI_METRICS:
        um = UCI_METRICS.get("model", {})
        ub = UCI_METRICS.get("baseline", {})
        u1, u2, u3, u4 = st.columns(4)
        u1.metric("UCI held-out rows", UCI_METRICS.get("test_rows", "—"))
        u2.metric("Model accuracy", f'{um.get("accuracy", 0) * 100:.1f}%')
        u3.metric("Spam recall", f'{um.get("recall_spam", 0) * 100:.1f}%')
        u4.metric("Baseline accuracy", f'{ub.get("accuracy", 0) * 100:.1f}%')
        notice("UCI labels are spam/ham, not pure phishing or financial fraud. These results must be presented as a separate English spam baseline.", "warning")
    else:
        notice("The optional UCI SMS Spam Collection model has not been trained in this package. Run TRAIN_ENGLISH_UCI_MODEL.bat on a connected Windows computer if you want to reproduce that separate baseline.", "warning")

    st.markdown("### Current capability boundaries")
    show_safe_steps([
        "The bundled classifier was trained on a small synthetic dataset and is not a validated international detector.",
        "The URL inspector is structural only: it does not query live reputation feeds, resolve DNS or follow redirects.",
        "The email tool reviews pasted header fields; it does not perform a full email authentication validation.",
        "The attachment tool checks filenames only; it does not inspect file bytes or detect malware.",
        "The application does not connect to inboxes, block attacks or provide a guarantee of legitimacy.",
    ])

    st.markdown("### Research roadmap")
    show_safe_steps([
        "Train and test on public, clearly labelled data with a separate test set that was not used for model selection.",
        "Build a consented international phishing dataset and report precision, recall and false positives separately by language.",
        "Test on unseen campaigns and have independent reviewers label difficult borderline examples.",
    ])

    st.markdown("### Credits and reproducibility")
    st.markdown(
        "- **Current bundled dataset:** 136 AI-assisted synthetic message examples. See `data/DATASET_CARD.md` and `data/SOURCES.md`.\n"
        "- **Optional public dataset:** [UCI SMS Spam Collection](https://archive.ics.uci.edu/dataset/228/sms), downloaded only when the optional trainer is run.\n"
        "- **Text model:** scikit-learn word + character TF-IDF with Logistic Regression.\n"
        "- **Application framework:** Streamlit.\n"
        "- **AI assistance:** ChatGPT assisted with project design, code and documentation and should be acknowledged in the competition credits."
    )


# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------
st.markdown(
    '<div class="footer-line"><b>FraudBeacon AI</b> · International student research MVP · AI + Finance<br>'
    'Use as a cybersecurity-awareness and triage aid only. Verify important requests independently. '
    'No result is a guarantee that a message, URL or file is safe.</div>',
    unsafe_allow_html=True,
)
