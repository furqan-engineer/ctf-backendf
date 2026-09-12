"""Job store, with two backends behind the same four functions.

- In-memory dict: fine on Railway/Fly/a VPS, where your app is one persistent
  container and every request hits the same process.
- Redis (or Vercel KV, which speaks the Redis protocol): required as soon as
  your host autoscales across multiple instances - e.g. Vercel Functions -
  because whichever instance handles GET /api/jobs/{id} might not be the one
  that handled POST /api/solve. Set REDIS_URL to switch to this backend;
  nothing else in the app needs to change.
"""
from __future__ import annotations

import threading
import time
import uuid

from app.config import get_settings
from app.schemas import JobRecord, JobStatus, SolveResult

_lock = threading.Lock()
_jobs: dict[str, JobRecord] = {}
_redis_client = None  # lazily created; only imported if REDIS_URL is set


def _redis():
    global _redis_client
    if _redis_client is None:
        import redis  # local import: keeps redis optional for Railway-only users

        _redis_client = redis.Redis.from_url(get_settings().redis_url, decode_responses=True)
    return _redis_client


def _use_redis() -> bool:
    return bool(get_settings().redis_url)


def _key(job_id: str) -> str:
    return f"ctf-job:{job_id}"


def create_job() -> JobRecord:
    job = JobRecord(job_id=uuid.uuid4().hex, status=JobStatus.PENDING, created_at=time.time())
    if _use_redis():
        _redis().set(_key(job.job_id), job.model_dump_json(), ex=get_settings().job_ttl_seconds)
    else:
        with _lock:
            _jobs[job.job_id] = job
            _sweep_locked()
    return job


def get_job(job_id: str) -> JobRecord | None:
    if _use_redis():
        raw = _redis().get(_key(job_id))
        return JobRecord.model_validate_json(raw) if raw else None
    with _lock:
        return _jobs.get(job_id)


def _save(job: JobRecord) -> None:
    if _use_redis():
        _redis().set(_key(job.job_id), job.model_dump_json(), ex=get_settings().job_ttl_seconds)
    else:
        with _lock:
            _jobs[job.job_id] = job


def mark_running(job_id: str) -> None:
    job = get_job(job_id)
    if job:
        job.status = JobStatus.RUNNING
        _save(job)


def mark_done(job_id: str, result: SolveResult) -> None:
    job = get_job(job_id)
    if job:
        job.status = JobStatus.DONE
        job.result = result
        _save(job)


def mark_error(job_id: str, error: str) -> None:
    job = get_job(job_id)
    if job:
        job.status = JobStatus.ERROR
        job.error = error
        _save(job)


def _sweep_locked() -> None:
    """In-memory backend only - Redis/KV expire keys natively via `ex=`."""
    ttl = get_settings().job_ttl_seconds
    cutoff = time.time() - ttl
    expired = [jid for jid, job in _jobs.items() if job.created_at < cutoff]
    for jid in expired:
        del _jobs[jid]
