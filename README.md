# AuditAI

AuditAI is a hybrid smart contract auditing platform that combines deterministic Slither static analysis with constrained Gemini natural-language reasoning.

## Architecture

- **Backend:** Python 3.11, FastAPI, SQLAlchemy, PostgreSQL.
- **Security engine:** Slither executed through an isolated subprocess.
- **Compiler manager:** `solc-select` installs and activates the Solidity compiler version detected from `pragma solidity`.
- **LLM layer:** Gemini explains only normalized Slither findings. It is explicitly prohibited from inventing findings.
- **Reporting:** ReportLab generates PDF audit reports with severity badges and remediation guidance.
- **Frontend:** React 18, Vite, Tailwind CSS dashboard with upload and real-time audit status polling.

## Section guide

- `backend/app/config.py` — loads database, Gemini, timeout, and CORS settings from `.env` or `backend/.env`.
- `backend/app/main.py` — exposes upload/status/report endpoints and coordinates the full audit pipeline.
- `backend/app/services/pragma.py` — reads Solidity pragma expressions and chooses a concrete compiler version token.
- `backend/app/services/solc.py` — runs `solc-select install` and `solc-select use` for the detected compiler.
- `backend/app/services/slither.py` — writes the upload to a temporary file, runs `slither --json -`, deletes the temp file, and normalizes findings.
- `backend/app/services/gemini.py` — calls Gemini with only Slither findings plus untrusted contract text wrapped in `###CONTRACT###` delimiters.
- `backend/app/services/report.py` — renders the PDF report using ReportLab.
- `frontend/src/main.jsx` — contains the upload, status, findings, and PDF-download UI sections.
- `frontend/src/api.js` — centralizes browser calls to the FastAPI backend.

## Security workflow

1. Upload a `.sol` file from the dashboard.
2. The API reads the Solidity pragma and selects a concrete compiler version for `solc-select install` and `solc-select use`.
3. Slither runs with `--json -` against a temporary contract file; the temporary directory is removed immediately after analysis.
4. Slither JSON is normalized into findings with `vulnerability_type`, `severity`, `function_name`, and `line_number`.
5. Gemini receives a constrained prompt containing only the Slither finding plus code wrapped in `###CONTRACT###` delimiters.
6. Findings and the generated PDF report are persisted to PostgreSQL.

## Gemini API key setup

The Gemini key is read from `GEMINI_API_KEY`. Keep real keys in a private `.env` file or a deployment secret manager; do not commit them.

```bash
cp .env.example backend/.env
# Edit backend/.env and set GEMINI_API_KEY to your Gemini API key.
```

The app also supports:

- `GEMINI_MODEL` — model name for Gemini `generateContent` calls.
- `GEMINI_TIMEOUT_SECONDS` — timeout for each explanation request.
- `CORS_ORIGINS` — comma-separated frontend origins allowed to call the API.

## Backend setup

```bash
cd backend
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

The backend expects PostgreSQL, Slither, and solc-select to be available in the runtime environment.

## Frontend setup

```bash
cd frontend
npm install
npm run dev
```

Set `VITE_API_BASE_URL` if the FastAPI server is not running on `http://localhost:8000`.

## API endpoints

- `POST /api/audits` — upload a Solidity file and enqueue analysis.
- `GET /api/audits/{audit_id}` — poll audit status, findings, and report metadata.
- `GET /api/audits/{audit_id}/report` — download the generated PDF report.
- `GET /health` — health check.

## Constraint

AuditAI does **not** generate audit findings with the LLM alone. Gemini only explains and remediates findings already emitted by Slither.
