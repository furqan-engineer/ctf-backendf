from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, Form, HTTPException, UploadFile

from app.config import get_settings
from app.gemini_client import ask_gemini
from app.job_store import create_job, get_job, mark_done, mark_error, mark_running
from app.pipeline import run_pipeline
from app.schemas import JobAccepted, JobStatusResponse, SolveResult
from app.workspace import new_workspace, save_upload

logger = logging.getLogger("ctf_backend")
router = APIRouter()


@router.post("/solve", response_model=JobAccepted, status_code=200)
async def solve(
    text: str = Form(default=""),
    files: list[UploadFile] | None = None,
):
    """Runs the full pipeline inline and returns once it's done.

    Deliberately NOT using FastAPI BackgroundTasks here: on autoscaled/
    serverless hosts (Vercel Functions and similar) there's no guarantee a
    function keeps running after it has sent its response, so a fire-and-
    forget background task can simply get killed mid-analysis. Awaiting the
    work inline works the same way on a persistent host (Railway) and a
    serverless one - just make sure your platform's request/function timeout
    is long enough for the tool pipeline (see README).

    The job_id + /api/jobs/{id} endpoint are kept so the existing frontend's
    polling flow keeps working unchanged - by the time it starts polling, the
    job is already marked done.
    """
    settings = get_settings()
    files = files or []

    if len(files) > settings.max_files_per_request:
        raise HTTPException(400, f"Too many files (max {settings.max_files_per_request})")

    ws = new_workspace()
    job = None
    try:
        job = create_job()
        mark_running(job.job_id)
    except Exception as exc:
        # infra-level failure (e.g. a bad/unreachable REDIS_URL) - there's no
        # job to report status on, so this has to be a real HTTP error
        ws.cleanup()
        logger.exception("could not create job")
        raise HTTPException(500, f"could not start job: {exc}") from exc

    try:
        total_bytes = 0
        for f in files:
            content = await f.read()
            total_bytes += len(content)
            if total_bytes > settings.max_upload_bytes:
                raise HTTPException(400, f"Upload too large (max {settings.max_upload_mb} MB total)")
            save_upload(ws, f.filename or "upload", content)

        # tool execution is blocking (subprocess) - run it off the event loop
        categories, tool_results = await asyncio.to_thread(run_pipeline, text, list(ws.files), ws)
        flag, reasoning, raw = await asyncio.to_thread(ask_gemini, text, categories, tool_results)

        result = SolveResult(
            flag=flag,
            reasoning=reasoning,
            categories=categories,
            tool_results=tool_results,
            raw_model_output=raw,
        )
        mark_done(job.job_id, result)
    except HTTPException as exc:
        mark_error(job.job_id, exc.detail)
        raise
    except Exception as exc:
        # a failure *within* an already-created job (bad file, tool crash,
        # Gemini error, ...) is recorded on the job and still a 200 response -
        # the frontend reads the real error out of job.status/job.error, same
        # as it always has
        logger.exception("job %s failed", job.job_id)
        mark_error(job.job_id, str(exc))
    finally:
        ws.cleanup()

    return JobAccepted(job_id=job.job_id)


@router.get("/jobs/{job_id}", response_model=JobStatusResponse)
async def get_job_status(job_id: str):
    job = get_job(job_id)
    if job is None:
        raise HTTPException(404, "job not found (it may have expired)")
    return JobStatusResponse(job_id=job.job_id, status=job.status, result=job.result, error=job.error)
