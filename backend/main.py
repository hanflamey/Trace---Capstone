import shutil
import uuid
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from backend import config
from backend.pipeline import mitre, orchestrator

# Generated deliverables, keyed by report id, for the download endpoints.
GENERATED_REPORTS = {}


@asynccontextmanager
async def lifespan(app):
    """
    Run once before the server accepts requests.

    Validates configuration loudly, then loads the MITRE ATT&CK bundle so the
    first analysis is not delayed by parsing ~50 MB of STIX data.

    Every print uses flush=True because uvicorn's --reload runs the app in a
    subprocess with buffered stdout; without it these messages can appear long
    after the events they describe, making a slow startup look like a hang.
    """
    problems = config.check_startup()
    if problems:
        print("\n" + "=" * 70, flush=True)
        print("  TRACE CONFIGURATION PROBLEMS", flush=True)
        print("=" * 70, flush=True)
        for problem in problems:
            print(f"  - {problem}\n", flush=True)
        print("=" * 70 + "\n", flush=True)
    else:
        print(f"[startup] configuration OK - local LLM at "
              f"{config.LOCAL_LLM_URL}", flush=True)

    print("[startup] loading MITRE ATT&CK data (takes a few seconds) ...",
          flush=True)
    try:
        mitre.preload()
        print("[startup] MITRE ATT&CK data ready", flush=True)
    except Exception as error:
        # A MITRE failure must not stop the server booting; it resurfaces at
        # analysis time with more context if it actually matters.
        print(f"[startup] WARNING: could not load MITRE data: {error}",
              flush=True)

    print("[startup] TRACE is ready - open http://localhost:8000", flush=True)
    yield


app = FastAPI(
    title="TRACE",
    version="3.0",
    description="Threat Reconnaissance & Artifact Correlation Engine",
    lifespan=lifespan,
)

app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])


def _save_upload(upload: Optional[UploadFile]):
    """
    Write one uploaded file to the uploads directory and return its path.

    A random prefix keeps concurrent analyses of identically named files from
    overwriting each other. Returns None when no file was supplied.
    """
    if not upload or not upload.filename:
        return None

    destination = config.UPLOAD_DIR / f"{uuid.uuid4().hex[:8]}_{upload.filename}"
    with open(destination, "wb") as handle:
        shutil.copyfileobj(upload.file, handle)
    return str(destination)


@app.get("/health")
def health():
    """
    Report liveness and the configuration the RUNNING server actually loaded.

    Sent with no-store because a cached /health response is actively
    misleading - the entire purpose of this endpoint is to show current state.
    """
    problems = config.check_startup()
    payload = {
        "status":   "ok" if not problems else "misconfigured",
        "problems": problems,
        "env_file": {"path": str(config.ENV_FILE),
                     "exists": config.ENV_FILE.exists()},
        "config":   config.summary(),
    }
    return JSONResponse(
        payload,
        headers={"Cache-Control": "no-store, no-cache, must-revalidate",
                 "Pragma": "no-cache"},
    )


@app.post("/analyze")
# Backend entry point
async def analyze(
    # --- artifact uploads (any subset; parsed CSV exports only) ----------
    amcache:   Optional[UploadFile] = File(None),
    prefetch:  Optional[UploadFile] = File(None),
    shimcache: Optional[UploadFile] = File(None),

    # --- chain-of-custody metadata --------------------------------------
    case_id:     str = Form(""),
    examiner:    str = Form(""),
    acquisition: str = Form(""),
    md5:         str = Form(""),
    sha1_image:  str = Form(""),
):
    """
    Run the full TRACE pipeline over the uploaded artifacts.

    Returns the analysis summary and findings as JSON. The PDF and CSV are
    fetched separately from /report/{id} and /export/{id}.
    """
    uploads = {
        "amcache":   _save_upload(amcache),
        "prefetch":  _save_upload(prefetch),
        "shimcache": _save_upload(shimcache),
    }

    if not any(uploads.values()):
        raise HTTPException(
            400,
            "Upload at least one CSV: an Amcache, Prefetch or ShimCache export "
            "produced by the matching Eric Zimmerman tool.",
        )

    # CSV only - the raw artifacts must be parsed before upload.
    for slot, upload in (("amcache", amcache), ("prefetch", prefetch),
                         ("shimcache", shimcache)):
        if uploads[slot] and not upload.filename.lower().endswith(".csv"):
            raise HTTPException(
                400,
                f"The {slot} upload must be a .csv file. Parse the raw artifact "
                f"with the matching Eric Zimmerman tool first, then upload the "
                f"CSV it produces.",
            )

    chain_of_custody = {
        key: value for key, value in {
            "case_id":     case_id,
            "examiner":    examiner,
            "acquisition": acquisition,
            "md5":         md5,
            "sha1_image":  sha1_image,
        }.items() if value
    }

    try:
        result = orchestrator.run_pipeline(uploads, chain_of_custody or None)

    except ValueError as error:
        # Unparseable or empty artifacts.
        raise HTTPException(422, str(error))
    except RuntimeError as error:
        # Local LLM unreachable, MITRE data unavailable.
        raise HTTPException(503, str(error))
    except Exception as error:
        import traceback
        traceback.print_exc()
        raise HTTPException(500, f"Pipeline error: {error}")

    # Keep the deliverable paths server-side, strip them from the response.
    GENERATED_REPORTS[result["report_id"]] = {
        "pdf": result.pop("_pdf_path"),
        "csv": result.pop("_csv_path"),
    }
    return result


@app.get("/report/{report_id}")
def get_report(report_id: str):
    """Download the PDF forensic report for a completed analysis."""
    entry = GENERATED_REPORTS.get(report_id)
    if not entry:
        raise HTTPException(404, "Unknown report id.")
    return FileResponse(entry["pdf"], media_type="application/pdf",
                        filename=f"TRACE_report_{report_id}.pdf")


@app.get("/export/{report_id}")
def get_export(report_id: str):
    """Download the findings CSV for a completed analysis."""
    entry = GENERATED_REPORTS.get(report_id)
    if not entry:
        raise HTTPException(404, "Unknown report id.")
    return FileResponse(entry["csv"], media_type="text/csv",
                        filename=f"TRACE_findings_{report_id}.csv")


# --- frontend ---------------------------------------------------------------
if config.FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(config.FRONTEND_DIR)),
              name="static")


@app.get("/")
def index():
    """
    Serve the dashboard.

    Sent with no-store so an edited dashboard appears on a normal refresh
    instead of requiring the analyst to know about hard-reloading.
    """
    index_file = config.FRONTEND_DIR / "index.html"
    if index_file.exists():
        return FileResponse(
            str(index_file), media_type="text/html",
            headers={"Cache-Control": "no-store, no-cache, must-revalidate"},
        )
    raise HTTPException(404, "Frontend not found. Expected frontend/index.html.")
