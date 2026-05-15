from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration for the AuditAI API.

    Each field maps to an environment variable so deployments can change
    database, Gemini, and browser-access settings without code edits. The
    settings loader checks both `.env` and `backend/.env` so the API works when
    launched from either the repository root or the backend directory.
    """

    model_config = SettingsConfigDict(env_file=(".env", "backend/.env"), env_file_encoding="utf-8", extra="ignore")

    # Application metadata used by FastAPI docs and health/debug displays.
    app_name: str = "AuditAI"

    # PostgreSQL database where users, audit sessions, findings, and PDFs live.
    database_url: str = Field(
        default="postgresql+psycopg://auditai:auditai@localhost:5432/auditai",
        alias="DATABASE_URL",
    )

    # Gemini settings. GEMINI_API_KEY must be supplied from a private .env file
    # or deployment secret manager; never hard-code real keys in source control.
    gemini_api_key: str | None = Field(default=None, alias="GEMINI_API_KEY")
    gemini_model: str = Field(default="gemini-1.5-flash", alias="GEMINI_MODEL")
    gemini_timeout_seconds: float = Field(default=45.0, alias="GEMINI_TIMEOUT_SECONDS")

    # Frontend origins allowed to call the API from browsers.
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"], alias="CORS_ORIGINS")

    @field_validator("cors_origins", mode="before")
    @classmethod
    def split_cors_origins(cls, value: str | list[str]) -> list[str]:
        """Allow CORS_ORIGINS as either JSON/list or comma-separated env text."""

        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value


@lru_cache
def get_settings() -> Settings:
    """Return cached settings so services share the same validated config."""

    return Settings()
