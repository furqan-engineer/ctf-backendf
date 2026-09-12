from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.0-flash"

    max_upload_mb: int = 50
    max_files_per_request: int = 10
    tool_timeout_seconds: int = 25
    job_ttl_seconds: int = 3600
    allowed_origins: str = "*"

    # If set, jobs are stored in Redis/Vercel KV instead of in-process memory.
    # Required on Vercel (or any autoscaled/multi-instance host) because the
    # instance that handles /api/solve is not guaranteed to be the same one
    # that later handles /api/jobs/{id} - an in-memory dict would 404.
    # Not required on Railway (single persistent container).
    redis_url: str = ""

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024

    @property
    def cors_origins(self) -> list[str]:
        if self.allowed_origins.strip() == "*":
            return ["*"]
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
