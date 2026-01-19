from __future__ import annotations

from pathlib import Path

import streamlit as st

from scanner import report_to_json, scan_pdf

st.set_page_config(page_title="PDF Sentry", page_icon="🛡️", layout="wide")

st.markdown("""
    <style>
    .stApp {
        background-color: #0e1117;
    }
    .main-header {
        background: linear-gradient(90deg, #1a1d29 0%, #2d3748 100%);
        padding: 2.5rem 2rem;
        border-radius: 8px;
        margin-bottom: 2rem;
        border: 1px solid #2d3748;
    }
    .main-header h1 {
        color: #e2e8f0;
        margin: 0;
        font-size: 2rem;
        font-weight: 600;
        letter-spacing: -0.5px;
    }
    .main-header p {
        color: #94a3b8;
        margin: 0.5rem 0 0 0;
        font-size: 1rem;
    }
    .stMetric {
        background: #1a1d29;
        padding: 1rem;
        border-radius: 6px;
        border: 1px solid #2d3748;
    }
    .stMetric label {
        color: #94a3b8 !important;
    }
    .stMetric [data-testid="stMetricValue"] {
        color: #e2e8f0 !important;
    }
    .section-header {
        color: #e2e8f0;
        font-size: 1.25rem;
        font-weight: 500;
        margin: 2.5rem 0 1rem 0;
        padding-bottom: 0.75rem;
        border-bottom: 1px solid #2d3748;
    }
    div[data-testid="stExpander"] {
        background: #1a1d29;
        border: 1px solid #2d3748;
        border-radius: 6px;
        margin-bottom: 0.5rem;
    }
    .upload-info {
        background: #1a1d29;
        border: 2px dashed #2d3748;
        border-radius: 8px;
        padding: 3rem 2rem;
        text-align: center;
        margin: 1rem 0;
    }
    .upload-info h3 {
        color: #e2e8f0;
        margin: 0 0 0.5rem 0;
        font-weight: 500;
    }
    .upload-info p {
        color: #64748b;
        margin: 0.25rem 0;
    }
    .risk-critical {
        border-left: 3px solid #dc2626;
    }
    .risk-high {
        border-left: 3px solid #ea580c;
    }
    .risk-medium {
        border-left: 3px solid #ca8a04;
    }
    .risk-low {
        border-left: 3px solid #059669;
    }
    [data-testid="stSidebar"] {
        background-color: #0e1117;
    }
    </style>
""", unsafe_allow_html=True)

# Header
st.markdown("""
    <div class="main-header">
        <h1>PDF Sentry</h1>
        <p>Professional PDF Exploit Scanner for Defensive Security</p>
    </div>
""", unsafe_allow_html=True)

# Sidebar configuration
with st.sidebar:
    st.subheader("Configuration")
    st.divider()
    
    st.markdown("**Tool Paths**")
    didier_dir = st.text_input(
        "DidierStevensSuite folder path",
        value=str((Path.cwd() / "DidierStevensSuite").resolve()),
        help="Clone DidierStevensSuite next to this repo, or point to it here.",
    )
    
    st.divider()
    
    st.markdown("**Scan Options**")
    run_qpdf = st.checkbox("Enable qpdf validation & rewrite", value=True)
    run_clamav = st.checkbox("Enable ClamAV scanning", value=False)
    
    st.divider()
    
    st.caption("Static analysis tool for identifying potentially malicious PDF features. Always practice safe handling of untrusted files.")

# File upload section
st.markdown("<div class='section-header'>Upload PDF File</div>", unsafe_allow_html=True)
uploaded = st.file_uploader(
    "Select a PDF file to scan for exploits and malicious features",
    type=["pdf"],
    help="Upload a PDF file for comprehensive security analysis"
)

if uploaded is None:
    st.markdown("""
        <div class='upload-info'>
            <h3>Upload a PDF to Begin Analysis</h3>
            <p>Drag and drop a file or click to browse</p>
            <p style='margin-top: 1rem;'>Supports static analysis including keyword detection, structure validation, and optional antivirus scanning</p>
        </div>
    """, unsafe_allow_html=True)
    st.stop()

pdf_bytes = uploaded.getvalue()

didier_path = Path(didier_dir).expanduser().resolve()
if not didier_path.exists():
    didier_path = None

# Scanning phase
st.markdown("<div class='section-header'>Scan Results</div>", unsafe_allow_html=True)

with st.spinner("Analyzing PDF file..."):
    report = scan_pdf(
        pdf_bytes=pdf_bytes,
        original_name=uploaded.name,
        didier_path=didier_path,
        run_clamav=run_clamav,
        run_qpdf=run_qpdf,
    )

# Risk level styling
risk_colors = {
    "CRITICAL": "risk-critical",
    "HIGH": "risk-high",
    "MEDIUM": "risk-medium",
    "LOW": "risk-low",
}
risk_class = risk_colors.get(report.risk_level.upper(), "risk-low")

# Metrics display
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown(f"<div class='stMetric {risk_class}'>", unsafe_allow_html=True)
    st.metric("Risk Level", report.risk_level)
    st.markdown("</div>", unsafe_allow_html=True)

with col2:
    st.metric("Risk Score", f"{report.risk_score}/100")

with col3:
    st.metric("File Size", f"{report.file_size:,} bytes")

with col4:
    st.metric("SHA-256", report.sha256[:16] + "…")

# Highlights section
st.markdown("<div class='section-header'>Security Highlights</div>", unsafe_allow_html=True)

if report.highlights:
    for h in report.highlights:
        st.warning(h)
else:
    st.success("No high-signal risky features detected by keyword scan (not proof of safety).")

# PDFID analysis
st.markdown("<div class='section-header'>PDFID Keyword Analysis</div>", unsafe_allow_html=True)

if report.pdfid_counts:
    col_a, col_b = st.columns(2)
    items = list(report.pdfid_counts.items())
    mid = (len(items) + 1) // 2
    
    with col_a:
        for key, value in items[:mid]:
            st.metric(key, value)
    
    with col_b:
        for key, value in items[mid:]:
            st.metric(key, value)
else:
    st.info("No PDFID data available")

# Tool output section
st.markdown("<div class='section-header'>Tool Output Details</div>", unsafe_allow_html=True)

for t in report.tools:
    status = "✓" if t.ok else "✗"
    with st.expander(f"{status} {t.name} — {t.note}"):
        if t.stderr.strip():
            st.markdown("**Standard Error:**")
            st.code(t.stderr.strip(), language="text")
        if t.stdout.strip():
            st.markdown("**Standard Output:**")
            st.code(t.stdout.strip(), language="text")
        if not t.stdout.strip() and not t.stderr.strip():
            st.info("No output generated")

# Export section
st.markdown("<div class='section-header'>Export & Download</div>", unsafe_allow_html=True)

export_col1, export_col2 = st.columns(2)

with export_col1:
    report_json = report_to_json(report)
    st.download_button(
        "Download JSON Report",
        data=report_json.encode("utf-8"),
        file_name=f"{uploaded.name}.pdf_sentry_report.json",
        mime="application/json",
        use_container_width=True
    )

with export_col2:
    if report.rebuilt_pdf_path:
        try:
            rebuilt_bytes = Path(report.rebuilt_pdf_path).read_bytes()
            st.download_button(
                "Download qpdf-rebuilt PDF",
                data=rebuilt_bytes,
                file_name=f"{uploaded.name}.rebuilt.pdf",
                mime="application/pdf",
                use_container_width=True
            )
        except Exception:
            st.warning("Could not load rebuilt PDF for download (temp file missing).")
    else:
        st.button("Download qpdf-rebuilt PDF", disabled=True, use_container_width=True)
        st.caption("Rebuild not available (qpdf not enabled)")

if report.rebuilt_pdf_path:
    st.caption("Rewrite can break some malicious tricks, but is not a safety guarantee.")