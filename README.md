# PDF Sentry for Defensive PDF Screening Tool (Didier Stevens)

PDF Sentry is a local, static PDF inspection tool designed to help identify potentially risky features in PDF files before opening them. It combines multiple open-source analysis utilities into a single interface for quick triage and reporting.

This tool is intended for **defensive inspection only**. It does not execute or render PDFs.

---

## What It Does

PDF Sentry performs layered static analysis using:

- **pdfid.py (Didier Stevens)**  
  Fast keyword scanning for high-risk PDF features such as JavaScript, OpenAction, embedded files, launch actions, and object streams.

- **pdf-parser.py (Didier Stevens)**  
  Object-level searches to confirm the presence of suspicious structures.

- **qpdf (optional)**  
  Structural validation and optional PDF rewrite to remove malformed or hidden structures.

- **SHA-256 hashing**  
  File fingerprinting for correlation with malware databases or incident reports.

Results are summarized as:
- Risk level (Low / Medium / High)
- Numeric risk score
- Highlighted indicators
- Full tool output per scan step
- Exportable JSON report

---

## Why This Exists

Many PDF-based attacks rely on features that are not visible to users, such as:
- auto-triggered actions when the file opens
- embedded payloads
- obfuscated object streams
- form-based scripting

PDF Sentry is meant to provide **pre-execution visibility** into these structures so that users can decide whether a file should be opened in a sandbox, virtual machine, or not at all.

This is not a malware detection engine. It is a **triage and inspection tool**.

---

## Requirements

- Python 3.10+
- pip
- Streamlit

Optional but recommended:
- `qpdf` (for structural validation and rewrite)

Didier Stevens Suite is required and should be cloned next to this repository.

---

## Setup

Clone this repository:

```bash
git clone https://github.com/sabrinahaniff/pdf-sentry.git
cd pdf-sentry
```

Clone Didier Stevens Suite into the same directory:

```bash
git clone https://github.com/DidierStevens/DidierStevensSuite.git
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

## Install dependencies:

```bash
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```
## (Optional) Install qpdf:

# macOS (Homebrew):

```bash
brew install qpdf
```

# Ubuntu:

```bash
sudo apt install qpdf
```

## Running the App

```bash
streamlit run app.py
```

Then open the browser link shown in the terminal (usually http://localhost:8501). Upload a PDF file and review the results in the dashboard.

### Output Overview

## Risk Score

Calculated using weighted indicators such as:

- OpenAction / Additional Actions
- JavaScript presence
- Embedded files
- Launch actions
- Object streams
- Scores are heuristic and meant for prioritization, not definitive classification.

## Highlights
Summarizes the most relevant indicators detected in the file.

- pdfid Keyword Counts
- Raw keyword statistics from pdfid.py for transparency and manual inspection.

## Tool Output

Individual results from each analysis step:

- pdfid scan
- pdf-parser object searches
- qpdf validation (if enabled)
- qpdf rewrite attempt (if enabled)

## Limitations
- No dynamic analysis
- No exploit detection
- No sandboxing
- No behavioral execution

A clean scan does not guarantee safety.

This tool is intended to be used alongside:

- antivirus scanning
- sandbox analysis
- virtual machines

## License
MIT License

This project uses third-party tools authored by Didier Stevens under their respective licenses.


---
