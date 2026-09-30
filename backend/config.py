import os
from pathlib import Path

# ============================================================================
# 1. PATHS
# ============================================================================
ROOT_DIR     = Path(__file__).resolve().parents[1]
DATA_DIR     = ROOT_DIR / "data"
UPLOAD_DIR   = DATA_DIR / "uploads"    # CSVs as uploaded by the analyst
OUTPUT_DIR   = DATA_DIR / "outputs"    # final PDF and CSV deliverables
CACHE_DIR    = DATA_DIR / "cache"      # threat-intel response caches
MITRE_DIR    = DATA_DIR / "mitre"      # ATT&CK STIX bundle
FRONTEND_DIR = ROOT_DIR / "frontend"

VT_CACHE_FILE           = CACHE_DIR / "virustotal_cache.json"
METADEFENDER_CACHE_FILE = CACHE_DIR / "metadefender_cache.json"
OTX_CACHE_FILE          = CACHE_DIR / "otx_cache.json"
MITRE_STIX_FILE         = MITRE_DIR / "enterprise-attack.json"

# Create every directory TRACE writes to, so a fresh clone runs immediately.
for directory in (UPLOAD_DIR, OUTPUT_DIR, CACHE_DIR, MITRE_DIR):
    directory.mkdir(parents=True, exist_ok=True)


# --- .env loading -----------------------------------------------------------
# Happens once, at import time. Editing .env while the server is running has NO
# effect, because uvicorn's --reload watches .py files rather than .env - the
# server must be restarted after a configuration change.
ENV_FILE = ROOT_DIR / ".env"

# Captured before load_dotenv runs, so check_startup() can detect an OS-level
# variable that was shadowing .env (see the override note below).
_OS_LLM_URL_BEFORE_DOTENV = os.environ.get("LOCAL_LLM_URL")

try:
    from dotenv import load_dotenv
    # override=True is deliberate. python-dotenv's default refuses to replace a
    # variable that already exists in the OS environment, so a stray
    # LOCAL_LLM_URL left over from an old shell session would silently win over
    # .env forever. For this project the .env file must always be authoritative.
    load_dotenv(ENV_FILE, override=True)
except ImportError:
    print("[config] WARNING: python-dotenv is not installed, so .env is being "
          "IGNORED. Run: pip install python-dotenv")


# ============================================================================
# 2. LOCAL LLM  (Stages 4 and 5: the two AI passes)
# ============================================================================
# Points at an LM Studio server exposing an OpenAI-compatible API.
#   MAX_TOKENS 4096   headroom for a model's <think> block plus its JSON answer
#   TEMPERATURE 0.05  near-deterministic, keeps structured JSON well-formed
#   BATCH_SIZE 10     entries per pass-1 call; pass 2 uses a smaller fixed size
LOCAL_LLM_URL         = os.getenv("LOCAL_LLM_URL", "").strip()
LOCAL_LLM_MODEL       = os.getenv("LOCAL_LLM_MODEL", "local-model").strip()
LOCAL_LLM_MAX_TOKENS  = int(os.getenv("LOCAL_LLM_MAX_TOKENS", "4096"))
LOCAL_LLM_TEMPERATURE = float(os.getenv("LOCAL_LLM_TEMPERATURE", "0.05"))
LOCAL_LLM_BATCH_SIZE  = int(os.getenv("LOCAL_LLM_BATCH_SIZE", "10"))


# ============================================================================
# 2b. REASONING ENGINE SELECTION  (which model answers Stages 4 and 5)
# ============================================================================
# "local"  -> LM Studio on this machine (the default, and the design TRACE
#             argues for: no prompt content ever leaves the workstation).
# "gemini" -> Google's hosted Gemini API, for accuracy comparison only.
#
# IMPORTANT, and worth stating in the write-up: with LLM_PROVIDER=gemini the
# FULL prompt - file names, paths, publishers, product names - is transmitted
# to Google. That is a materially different trust model from the local path,
# where only SHA-1 hashes are ever sent externally (to threat intelligence).
# Everything else is held identical between providers - the same prompts, the
# same batch sizes, the same MITRE validation and the same scoring - so that a
# comparison between them isolates the model as the only changed variable.
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "local").strip().lower()

GEMINI_API_KEY        = os.getenv("GEMINI_API_KEY", "").strip()
GEMINI_MODEL          = os.getenv("GEMINI_MODEL", "gemini-3.6-flash").strip()
GEMINI_THINKING_LEVEL = os.getenv("GEMINI_THINKING_LEVEL", "medium").strip()
GEMINI_MAX_TOKENS     = int(os.getenv("GEMINI_MAX_TOKENS", "65536"))

# Gemini's free tier limits requests per minute. TRACE issues its calls back to
# back with no pauses, so a case large enough to need several batches will trip
# that limit partway through and abort an analysis that was otherwise working.
# These two settings pace the calls and retry the ones that still fail.
GEMINI_REQUESTS_PER_MIN = int(os.getenv("GEMINI_REQUESTS_PER_MIN", "5"))
GEMINI_SECONDS_BETWEEN  = 60.0 / max(GEMINI_REQUESTS_PER_MIN, 1)
GEMINI_MAX_RETRIES      = int(os.getenv("GEMINI_MAX_RETRIES", "3"))


# ============================================================================
# 3. THREAT INTELLIGENCE  (Stage 3)
# ============================================================================
# All three sources are queried on every run. A source with no API key returns
# empty results silently, so there are no per-source switches to manage.

# How long to wait for a single lookup before giving up. Kept short: when a
# service is unreachable, a long timeout multiplied by every hash in the case
# turns a failed lookup into a stalled analysis.
TI_TIMEOUT = float(os.getenv("TI_TIMEOUT", "15"))

# Consecutive network failures before a source is abandoned for the rest of
# the run. Without this, an unreachable service costs TI_TIMEOUT seconds for
# EVERY hash - 60 hashes against a dead endpoint is a 15-minute stall for
# results that were never going to arrive.
TI_MAX_CONSECUTIVE_FAILURES = int(os.getenv("TI_MAX_CONSECUTIVE_FAILURES", "3"))

# --- VirusTotal ---
VT_API_KEY          = os.getenv("VT_API_KEY", "").strip()
VT_BASE_URL         = "https://www.virustotal.com/api/v3/files/"
VT_REQUESTS_PER_MIN = int(os.getenv("VT_REQUESTS_PER_MIN", "4"))   # free tier
VT_SECONDS_BETWEEN  = 60.0 / max(VT_REQUESTS_PER_MIN, 1)
VT_MAX_BACKOFF      = float(os.getenv("VT_MAX_BACKOFF", "60"))

# --- MetaDefender (OPSWAT) ---
METADEFENDER_API_KEY          = os.getenv("METADEFENDER_API_KEY", "").strip()
METADEFENDER_BASE_URL         = "https://api.metadefender.com/v4/hash"
METADEFENDER_REQUESTS_PER_MIN = int(os.getenv("METADEFENDER_REQUESTS_PER_MIN", "10"))
METADEFENDER_SECONDS_BETWEEN  = 60.0 / max(METADEFENDER_REQUESTS_PER_MIN, 1)
METADEFENDER_MAX_BACKOFF      = float(os.getenv("METADEFENDER_MAX_BACKOFF", "60"))

# --- AlienVault OTX ---
OTX_API_KEY          = os.getenv("OTX_API_KEY", "").strip()
OTX_BASE_URL         = "https://otx.alienvault.com/api/v1/indicators/file/"
OTX_REQUESTS_PER_MIN = int(os.getenv("OTX_REQUESTS_PER_MIN", "10"))
OTX_SECONDS_BETWEEN  = 60.0 / max(OTX_REQUESTS_PER_MIN, 1)
OTX_MAX_BACKOFF      = float(os.getenv("OTX_MAX_BACKOFF", "60"))


# ============================================================================
# 4. SEVERITY
# ============================================================================
# How many independent antivirus engines must flag a hash before TRACE treats
# it as confirmed malware. Below this the AI's judgement stands on its own.
TI_CONFIRM_THRESHOLD = int(os.getenv("TI_CONFIRM_THRESHOLD", "5"))

# Severity bands applied to the final 0-10 score.
SEV_CRITICAL = float(os.getenv("SEV_CRITICAL", "7.0"))
SEV_HIGH     = float(os.getenv("SEV_HIGH", "5.0"))
SEV_MEDIUM   = float(os.getenv("SEV_MEDIUM", "3.0"))


def check_startup():
    """
    Validate the configuration and return a list of human-readable problems.

    Called from main.py at server startup so misconfiguration is visible
    immediately, rather than surfacing thirty seconds into an analysis after
    the analyst has already uploaded evidence and waited.
    """
    problems = []

    if LLM_PROVIDER not in ("local", "gemini"):
        problems.append(
            f"LLM_PROVIDER is set to {LLM_PROVIDER!r}, which is not a valid "
            f"choice. Use 'local' (LM Studio) or 'gemini' (Google API)."
        )

    # --- checks that only apply to the local provider ---------------------
    # When running against Gemini there is no LM Studio server, so complaining
    # about LOCAL_LLM_URL would be a false alarm on every startup.
    if LLM_PROVIDER == "local":
        # A stray OS-level variable used to shadow .env before override=True was
        # set above. Surfacing it turns a future "my old value came back" mystery
        # into a one-line explanation.
        if (_OS_LLM_URL_BEFORE_DOTENV
                and _OS_LLM_URL_BEFORE_DOTENV != LOCAL_LLM_URL):
            problems.append(
                f"A Windows environment variable LOCAL_LLM_URL="
                f"{_OS_LLM_URL_BEFORE_DOTENV!r} exists and previously shadowed "
                f".env ({LOCAL_LLM_URL!r} is now correctly in use). Remove it with:"
                f" [Environment]::SetEnvironmentVariable('LOCAL_LLM_URL', $null, "
                f"'User')  then restart your terminal."
            )

        if not LOCAL_LLM_URL:
            location = (f"but {ENV_FILE} does not contain it" if ENV_FILE.exists()
                        else f"and no .env file exists at {ENV_FILE}")
            problems.append(
                f"LOCAL_LLM_URL is not set ({location}). TRACE cannot analyse "
                f"anything without a local LLM. Copy .env.example to .env, set "
                f"LOCAL_LLM_URL, then RESTART this server - .env is only read at "
                f"startup."
            )

    # --- checks that only apply to the Gemini provider --------------------
    if LLM_PROVIDER == "gemini":
        if not GEMINI_API_KEY:
            problems.append(
                f"LLM_PROVIDER is 'gemini' but GEMINI_API_KEY is not set in "
                f"{ENV_FILE}. Add the key, then RESTART this server - .env is "
                f"only read at startup."
            )

        # Fail here rather than three minutes into an analysis.
        try:
            import google.genai  # noqa: F401
        except ImportError:
            problems.append(
                "LLM_PROVIDER is 'gemini' but the google-genai package is not "
                "installed. Run: pip install google-genai"
            )

    return problems

def summary():
    """
    Describe the active configuration for the /health endpoint.

    Never includes API keys - only whether each one is present.
    """
    return {
        "trace_version": "3.0",
        # Which engine is actually answering Stages 4 and 5 on this run. Shown
        # first because every other LLM value below is only meaningful in the
        # context of the provider currently selected.
        "llm_provider": LLM_PROVIDER,
        "local_llm": {
            "url":         LOCAL_LLM_URL or None,
            "model":       LOCAL_LLM_MODEL if LOCAL_LLM_URL else None,
            "max_tokens":  LOCAL_LLM_MAX_TOKENS,
            "temperature": LOCAL_LLM_TEMPERATURE,
            "batch_size":  LOCAL_LLM_BATCH_SIZE,
        },
        "gemini": {
            "model":            GEMINI_MODEL,
            "thinking_level":   GEMINI_THINKING_LEVEL,
            "max_tokens":       GEMINI_MAX_TOKENS,
            "key_configured":   bool(GEMINI_API_KEY),
            "requests_per_min": GEMINI_REQUESTS_PER_MIN,
            "max_retries":      GEMINI_MAX_RETRIES,
        },
        "threat_intel_keys_configured": {
            "virustotal":   bool(VT_API_KEY),
            "metadefender": bool(METADEFENDER_API_KEY),
            "otx":          bool(OTX_API_KEY),
        },
        "ti_confirm_threshold": TI_CONFIRM_THRESHOLD,
        "severity_bands": {"critical": SEV_CRITICAL, "high": SEV_HIGH,
                           "medium": SEV_MEDIUM},
    }
