from pathlib import PurePath

from fastapi import BackgroundTasks, Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from sqlalchemy.orm import Session, selectinload

from .config import get_settings
from .database import SessionLocal, get_db, init_db
from .models import AuditSession, AuditStatus, Finding, Report
from .schemas import AuditSessionRead
from .services.gemini import explain_finding
from .services.pragma import read_pragma, select_installable_solc_version
from .services.report import build_pdf
from .services.slither import run_slither
from .services.solc import configure_solc

settings = get_settings()
app = FastAPI(title=settings.app_name, version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup() -> None:
    init_db()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


# Upload endpoint: the React dashboard sends a .sol file here. The handler
# stores an AuditSession quickly, then the expensive Slither/Gemini work runs
# in a background task so the browser can poll real-time status.
@app.post("/api/audits", response_model=AuditSessionRead, status_code=202)
async def create_audit(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> AuditSession:
    if not file.filename or not file.filename.endswith(".sol"):
        raise HTTPException(status_code=400, detail="Upload a Solidity .sol file.")

    raw = await file.read()
    try:
        source_code = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="Solidity file must be UTF-8 encoded.") from exc

    contract_name = PurePath(file.filename).name
    pragma = read_pragma(source_code)
    session = AuditSession(
        contract_name=contract_name,
        source_code=source_code,
        pragma_version=pragma,
        status=AuditStatus.queued,
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    background_tasks.add_task(_run_audit_pipeline, session.id)
    return _load_session(db, session.id)


# Status endpoint: the frontend polls this to show queued/analyzing/explaining/
# reporting/complete states plus findings as they are persisted.
@app.get("/api/audits/{audit_id}", response_model=AuditSessionRead)
def get_audit(audit_id: str, db: Session = Depends(get_db)) -> AuditSession:
    return _load_session(db, audit_id)


# Report endpoint: once ReportLab has generated the PDF, this returns the
# binary document as a download.
@app.get("/api/audits/{audit_id}/report")
def download_report(audit_id: str, db: Session = Depends(get_db)) -> Response:
    session = _load_session(db, audit_id)
    if not session.report:
        raise HTTPException(status_code=404, detail="Report is not ready yet.")
    return Response(
        content=session.report.pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{session.report.file_name}"'},
    )


def _load_session(db: Session, audit_id: str) -> AuditSession:
    session = (
        db.query(AuditSession)
        .options(selectinload(AuditSession.findings), selectinload(AuditSession.report))
        .filter(AuditSession.id == audit_id)
        .first()
    )
    if not session:
        raise HTTPException(status_code=404, detail="Audit session not found.")
    return session


async def _run_audit_pipeline(audit_id: str) -> None:
    """Execute the full Slither-first audit workflow for one session.

    Section map:
    1. Compiler setup uses pragma parsing + solc-select.
    2. Static analysis uses Slither JSON as the only finding source.
    3. Gemini explains each Slither finding without adding new findings.
    4. ReportLab builds the final PDF for download.
    """

    db = SessionLocal()
    try:
        session = _load_session(db, audit_id)
        session.status = AuditStatus.analyzing
        db.commit()

        compiler_version = select_installable_solc_version(session.pragma_version)
        await configure_solc(compiler_version)
        normalized_findings = await run_slither(session.source_code, session.contract_name)

        session.status = AuditStatus.explaining
        db.commit()
        for item in normalized_findings:
            reasoning = await explain_finding(session.source_code, item)
            finding = Finding(
                audit_session_id=session.id,
                vulnerability_type=item["vulnerability_type"],
                severity=item["severity"],
                function_name=item.get("function_name"),
                line_number=item.get("line_number"),
                detector=item.get("detector"),
                source_mapping=item.get("source_mapping"),
                slither_description=item["slither_description"],
                explanation=reasoning["explanation"],
                exploitability=reasoning["exploitability"],
                remediation_snippet=reasoning["remediation_snippet"],
            )
            db.add(finding)
        db.commit()

        session = _load_session(db, audit_id)
        session.status = AuditStatus.reporting
        db.commit()
        pdf = build_pdf(session)
        db.add(Report(audit_session_id=session.id, file_name=f"{session.contract_name}.audit.pdf", pdf_bytes=pdf))
        session.status = AuditStatus.complete
        db.commit()
    except Exception as exc:
        session = db.query(AuditSession).filter(AuditSession.id == audit_id).first()
        if session:
            session.status = AuditStatus.failed
            session.error_message = str(exc)
            db.commit()
    finally:
        db.close()
