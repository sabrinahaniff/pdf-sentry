from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


def run_cmd(args: List[str], timeout_s: int = 30) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        return 124, e.stdout or "", f"TIMEOUT after {timeout_s}s"
    except Exception as e:
        return 127, "", f"ERROR: {e!r}"


RISKY_KEYS = [
    "/JavaScript",
    "/JS",
    "/OpenAction",
    "/AA",
    "/Launch",
    "/EmbeddedFile",
    "/Filespec",
    "/XFA",
    "/AcroForm",
    "/RichMedia",
    "/ObjStm",
]

WEIGHTS = {
    "/Launch": 30,
    "/EmbeddedFile": 25,
    "/Filespec": 15,
    "/JavaScript": 25,
    "/JS": 10,
    "/OpenAction": 25,
    "/AA": 20,
    "/XFA": 15,
    "/AcroForm": 10,
    "/RichMedia": 20,
    "/ObjStm": 8,
}


@dataclass
class ToolResult:
    name: str
    ok: bool
    returncode: int
    stdout: str
    stderr: str
    note: str = ""


@dataclass
class ScanReport:
    file_name: str
    file_size: int
    sha256: str
    pdfid_counts: Dict[str, int]
    risk_score: int
    risk_level: str
    highlights: List[str]
    tools: List[ToolResult]
    rebuilt_pdf_path: Optional[str] = None


def sha256_file(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_pdfid_output(out: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for line in out.splitlines():
        m = re.match(r"^\s*(/\w+)\s+(\d+)", line.strip())
        if not m:
            continue
        k, v = m.group(1), int(m.group(2))
        counts[k] = v
    return counts


def clamp(n: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, n))


def compute_risk(counts: Dict[str, int]) -> Tuple[int, str, List[str]]:
    score = 0
    highlights: List[str] = []

    for k, w in WEIGHTS.items():
        c = counts.get(k, 0)
        if c > 0:
            score += w * (1 if c == 1 else 1 + min(3, c // 2))
            highlights.append(f"{k} present ({c})")

    score = clamp(score, 0, 100)

    if score >= 70:
        level = "HIGH"
    elif score >= 35:
        level = "MEDIUM"
    else:
        level = "LOW"

    if counts.get("/OpenAction", 0) or counts.get("/AA", 0):
        highlights.append("Auto-trigger actions detected (OpenAction/AA). Treat as high risk.")
    if counts.get("/Launch", 0):
        highlights.append("Launch actions can attempt external launching.")
    if counts.get("/EmbeddedFile", 0) or counts.get("/Filespec", 0):
        highlights.append("Embedded file indicators present (possible attached payloads).")
    if counts.get("/JavaScript", 0) or counts.get("/JS", 0):
        highlights.append("JavaScript indicators present.")
    if counts.get("/ObjStm", 0):
        highlights.append("Object streams present (often benign, but reduces visibility).")

    return score, level, highlights


def scan_pdf(
    pdf_bytes: bytes,
    original_name: str,
    didier_path: Optional[Path] = None,
    run_clamav: bool = False,
    run_qpdf: bool = True,
) -> ScanReport:
    with tempfile.TemporaryDirectory(prefix="pdf_sentry_") as td:
        td_path = Path(td)
        pdf_path = td_path / "input.pdf"
        pdf_path.write_bytes(pdf_bytes)

        size = pdf_path.stat().st_size
        digest = sha256_file(pdf_path)

        tools: List[ToolResult] = []
        pdfid_counts: Dict[str, int] = {}

        pdfid_py = None
        pdfparser_py = None

        if didier_path:
            pdfid_py = didier_path / "pdfid.py"
            pdfparser_py = didier_path / "pdf-parser.py"

        # attempt local relative folder 
        if pdfid_py is None:
            candidate = Path.cwd() / "DidierStevensSuite" / "pdfid.py"
            if candidate.exists():
                pdfid_py = candidate
        if pdfparser_py is None:
            candidate = Path.cwd() / "DidierStevensSuite" / "pdf-parser.py"
            if candidate.exists():
                pdfparser_py = candidate

        # pdfid
        if pdfid_py and pdfid_py.exists():
            rc, out, err = run_cmd(["python3", str(pdfid_py), str(pdf_path)], timeout_s=20)
            tools.append(ToolResult("pdfid.py", rc == 0, rc, out, err, note="Fast keyword indicator scan"))
            if rc == 0:
                pdfid_counts = parse_pdfid_output(out)
        else:
            tools.append(
                ToolResult(
                    "pdfid.py",
                    False,
                    127,
                    "",
                    "",
                    note="DidierStevensSuite not found. Clone it next to this repo or set didier_path in UI.",
                )
            )

        # pdf-parser searches
        if pdfparser_py and pdfparser_py.exists():
            for key in ["/JavaScript", "/OpenAction", "/AA", "/Launch", "/EmbeddedFile", "/XFA", "/RichMedia"]:
                rc, out, err = run_cmd(["python3", str(pdfparser_py), "-s", key, str(pdf_path)], timeout_s=30)
                tools.append(ToolResult(f"pdf-parser.py -s {key}", rc == 0, rc, out, err, note="Object keyword search"))
        else:
            tools.append(ToolResult("pdf-parser.py", False, 127, "", "", note="pdf-parser.py not found (DidierStevensSuite missing)."))

        rebuilt_pdf_path = None
        if run_qpdf:
            if which("qpdf"):
                rc, out, err = run_cmd(["qpdf", "--check", str(pdf_path)], timeout_s=30)
                tools.append(ToolResult("qpdf --check", rc == 0, rc, out, err, note="Structural validation"))

                rebuilt = td_path / "rebuilt.pdf"
                rc2, out2, err2 = run_cmd(["qpdf", str(pdf_path), str(rebuilt)], timeout_s=60)
                tools.append(ToolResult("qpdf rewrite", rc2 == 0, rc2, out2, err2, note="Rewrite/rebuild attempt"))
            if rebuilt.exists():
                persistent = Path(tempfile.gettempdir()) / f"pdf_sentry_rebuilt_{original_name}"
            try:
                persistent.write_bytes(rebuilt.read_bytes())
                rebuilt_pdf_path = str(persistent)
            except Exception:
                rebuilt_pdf_path = None
            else:
                tools.append(ToolResult("qpdf", False, 127, "", "", note="qpdf not installed or not in PATH"))

        if run_clamav:
            if which("clamscan"):
                rc, out, err = run_cmd(["clamscan", "--no-summary", str(pdf_path)], timeout_s=60)
                tools.append(ToolResult("clamscan", rc == 0, rc, out, err, note="Signature scan (second opinion)"))
            else:
                tools.append(ToolResult("clamscan", False, 127, "", "", note="ClamAV not installed or not in PATH"))

        score, level, highlights = compute_risk(pdfid_counts)

        return ScanReport(
            file_name=original_name,
            file_size=size,
            sha256=digest,
            pdfid_counts=pdfid_counts,
            risk_score=score,
            risk_level=level,
            highlights=highlights,
            tools=tools,
            rebuilt_pdf_path=rebuilt_pdf_path,
        )


def report_to_json(report: ScanReport) -> str:
    return json.dumps(asdict(report), indent=2)
