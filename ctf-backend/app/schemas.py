from enum import Enum
from typing import Any

from pydantic import BaseModel


class Category(str, Enum):
    CRYPTO = "crypto"
    STEGANOGRAPHY = "steganography"
    FORENSICS = "forensics"
    ARCHIVE = "archive"
    WEB = "web"
    NETWORK = "network"  # "launch instance" nc/host:port challenges (pwn/misc)
    MISC = "misc"


class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    ERROR = "error"


class ToolResult(BaseModel):
    tool: str
    ok: bool
    summary: str
    detail: str = ""  # truncated stdout/stderr, capped for size


class SolveResult(BaseModel):
    flag: str | None = None
    reasoning: str = ""
    categories: list[Category] = []
    tool_results: list[ToolResult] = []
    raw_model_output: str = ""


class JobRecord(BaseModel):
    job_id: str
    status: JobStatus
    created_at: float
    result: SolveResult | None = None
    error: str | None = None

    class Config:
        arbitrary_types_allowed = True


class JobAccepted(BaseModel):
    job_id: str
    status: JobStatus = JobStatus.PENDING


class JobStatusResponse(BaseModel):
    job_id: str
    status: JobStatus
    result: SolveResult | None = None
    error: str | None = None
