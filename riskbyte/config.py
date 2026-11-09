"""Configuration from environment variables. Fails closed: outside dev mode, tokens are mandatory."""
from __future__ import annotations
import os
from dataclasses import dataclass


class ConfigError(Exception):
    pass


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _bool(name: str, default: bool = False) -> bool:
    return _env(name, "1" if default else "0").strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Config:
    data_dir: str
    rules_dir: str
    intel_file: str
    bind: str
    port: int
    syslog_port: int
    admin_token: str
    analyst_token: str
    ingest_token: str
    license_path: str
    license_pubkey: str
    dev_mode: bool
    llm_provider: str           # none | ollama | openai | gemini
    llm_url: str
    llm_model: str
    llm_api_key: str
    llm_timeout: int
    llm_redact: bool            # pseudonymize hosts, users and private IPs before sending to a cloud model
    response_mode: str          # dry_run | webhook
    response_webhook: str
    response_secret: str
    protected_ips: list
    auto_close_low: bool
    retention_days: int

    @property
    def db_path(self) -> str:
        return os.path.join(self.data_dir, "riskbyte.db")


PROVIDER_DEFAULTS = {  # provider: (base url, default model). Check your provider's docs for current model names.
    "ollama": ("http://ollama:11434", "llama3.1:8b"),
    "openai": ("https://api.openai.com", "gpt-4o-mini"),
    "gemini": ("https://generativelanguage.googleapis.com", "gemini-2.0-flash"),
}


def _secret(name: str) -> str:
    """Read a secret from NAME, or from the file named by NAME_FILE (Docker/Kubernetes secrets)."""
    path = _env(name + "_FILE")
    if path:
        try:
            with open(path, encoding="utf-8") as f:
                return f.read().strip()
        except OSError as exc:
            raise ConfigError(f"cannot read {name}_FILE: {exc.strerror}") from None
    return _env(name).strip()


def load() -> Config:
    dev = _bool("RISKBYTE_DEV_MODE")
    provider = _env("RISKBYTE_LLM_PROVIDER", "ollama" if _env("RISKBYTE_LLM_URL") else "none").strip().lower()
    if provider not in ("none", "ollama", "openai", "gemini"):
        raise ConfigError("RISKBYTE_LLM_PROVIDER must be none, ollama, openai or gemini")
    cfg = Config(
        data_dir=_env("RISKBYTE_DATA_DIR", "./data"),
        rules_dir=_env("RISKBYTE_RULES_DIR", "./rules"),
        intel_file=_env("RISKBYTE_INTEL_FILE", "./intel/indicators.txt"),
        bind=_env("RISKBYTE_BIND", "0.0.0.0"),
        port=int(_env("RISKBYTE_PORT", "8080")),
        syslog_port=int(_env("RISKBYTE_SYSLOG_PORT", "5514")),
        admin_token=_env("RISKBYTE_ADMIN_TOKEN", "dev-admin" if dev else ""),
        analyst_token=_env("RISKBYTE_ANALYST_TOKEN", "dev-analyst" if dev else ""),
        ingest_token=_env("RISKBYTE_INGEST_TOKEN", "dev-ingest" if dev else ""),
        license_path=_env("RISKBYTE_LICENSE_PATH", "./license.rbl"),
        license_pubkey=_env("RISKBYTE_LICENSE_PUBKEY", "./vendor_public.pem"),
        dev_mode=dev,
        llm_provider=provider,
        llm_url=_env("RISKBYTE_LLM_URL", PROVIDER_DEFAULTS.get(provider, ("", ""))[0]),
        llm_model=_env("RISKBYTE_LLM_MODEL", PROVIDER_DEFAULTS.get(provider, ("", ""))[1]),
        llm_api_key=_secret("RISKBYTE_LLM_API_KEY"),
        llm_timeout=int(_env("RISKBYTE_LLM_TIMEOUT", "60")),
        llm_redact=_bool("RISKBYTE_LLM_REDACT", provider in ("openai", "gemini")),
        response_mode=_env("RISKBYTE_RESPONSE_MODE", "dry_run"),
        response_webhook=_env("RISKBYTE_RESPONSE_WEBHOOK", ""),
        response_secret=_env("RISKBYTE_RESPONSE_SECRET", ""),
        protected_ips=[x.strip() for x in _env("RISKBYTE_PROTECTED_IPS", "").split(",") if x.strip()],
        auto_close_low=_bool("RISKBYTE_AUTO_CLOSE_LOW", True),
        retention_days=int(_env("RISKBYTE_RETENTION_DAYS", "30")),
    )
    missing = [n for n, v in (("RISKBYTE_ADMIN_TOKEN", cfg.admin_token),
                              ("RISKBYTE_ANALYST_TOKEN", cfg.analyst_token),
                              ("RISKBYTE_INGEST_TOKEN", cfg.ingest_token)) if len(v) < 16 and not dev]
    if missing:
        raise ConfigError("Set strong (16+ char) values for: " + ", ".join(missing)
                          + " (or RISKBYTE_DEV_MODE=1 for local testing)")
    if provider in ("openai", "gemini") and not cfg.llm_api_key:
        raise ConfigError(f"{provider} needs RISKBYTE_LLM_API_KEY (or RISKBYTE_LLM_API_KEY_FILE)")
    if provider in ("openai", "gemini") and not cfg.llm_url.startswith("https://") and not dev:
        raise ConfigError("cloud LLM providers must use an https:// URL")
    if cfg.response_mode not in ("dry_run", "webhook"):
        raise ConfigError("RISKBYTE_RESPONSE_MODE must be dry_run or webhook")
    if cfg.response_mode == "webhook" and not (cfg.response_webhook and len(cfg.response_secret) >= 16):
        raise ConfigError("webhook mode needs RISKBYTE_RESPONSE_WEBHOOK and a 16+ char RISKBYTE_RESPONSE_SECRET")
    return cfg
