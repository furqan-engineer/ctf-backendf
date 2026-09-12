from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import router
from app.config import get_settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ctf_backend")

settings = get_settings()

app = FastAPI(
    title="CTF Solver Backend",
    description="Upload a challenge (text + files), get back a category, tool evidence, and a Gemini-reasoned flag.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api")


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Belt-and-suspenders: FastAPI's exception handlers run *inside*
    CORSMiddleware, so a response built here still gets CORS headers
    attached normally - unlike a truly unhandled exception, which skips
    CORSMiddleware entirely and shows up in the browser as a misleading
    "no Access-Control-Allow-Origin header" CORS error instead of the real
    500. Individual routes should still catch what they can (see
    app/api/routes.py) - this only exists to make sure nothing slips
    through uncaught, anywhere in the app.
    """
    logger.exception("unhandled exception on %s", request.url.path)
    return JSONResponse(status_code=500, content={"detail": f"internal error: {exc}"})


@app.get("/health")
async def health():
    return {"status": "ok"}
