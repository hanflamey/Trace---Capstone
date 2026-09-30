import time

from backend import config
from backend.pipeline import ai_engine, mitre

# Pass 2 entries are far larger than Pass 1 entries, so they are sent in small
# groups. Three at a time keeps each prompt focused without making one HTTP
# call per file.
PASS2_BATCH_SIZE = 3


def _get_client():
    """
    Return an OpenAI client pointed at the local LM Studio server.

    Returns None when no URL is configured or the openai package is missing,
    so callers can raise a clear error instead of a confusing import failure.
    """
    if not config.LOCAL_LLM_URL:
        return None

    try:
        from openai import OpenAI
    except ImportError:
        print("[local_llm] the openai package is not installed - "
              "run: pip install openai")
        return None

    base_url = config.LOCAL_LLM_URL.rstrip("/")

    # LM Studio serves /v1; tolerate the common /api/v1 typo.
    if base_url.endswith("/api/v1"):
        base_url = base_url.replace("/api/v1", "/v1")

    # LM Studio ignores the key, but the OpenAI client requires one.
    return OpenAI(base_url=base_url, api_key="lm-studio")


def _require_client():
    """
    Return a client or raise with an actionable message.

    Returns None when the Gemini provider is selected: that path builds its own
    client per call and has no LM Studio server to check, so there is nothing
    here to validate. The pass functions pass the result straight to _call(),
    which ignores it for Gemini.

    For the local provider, the usual cause of a missing client is a stale
    server rather than a missing setting, since .env is only read at import
    time - so the error says so.
    """
    if config.LLM_PROVIDER == "gemini":
        return None

    client = _get_client()
    if client:
        return client

    raise RuntimeError(
        f"No local LLM is configured (LOCAL_LLM_URL is empty).\n"
        f"  .env file: {config.ENV_FILE} "
        f"({'found' if config.ENV_FILE.exists() else 'MISSING'})\n"
        f"  If LOCAL_LLM_URL is set there, RESTART the server - .env is only "
        f"read at startup, so editing it while running has no effect."
    )


def _call(client, system_prompt, user_prompt, label):
    """
    Send one prompt to whichever engine is configured, return its raw text.

    This is the ONLY place in the pipeline that knows which provider is in use.
    Everything above it - prompt construction, batching, JSON parsing, MITRE
    validation, scoring - is provider-agnostic, so switching engines changes
    the model and nothing else. That is what makes a comparison between them
    meaningful rather than a comparison of two different pipelines.
    """
    if config.LLM_PROVIDER == "gemini":
        return _call_gemini(system_prompt, user_prompt, label)
    return _call_local(client, system_prompt, user_prompt, label)


def _call_local(client, system_prompt, user_prompt, label):
    """
    Send one prompt to the local LM Studio server and return its raw text.

    Raises RuntimeError with the underlying cause attached, because a failed
    LLM call means the analysis cannot complete and the analyst needs to know
    whether LM Studio is actually running.
    """
    print(f"[local_llm] -> {label}")

    try:
        response = client.chat.completions.create(
            model=config.LOCAL_LLM_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
            temperature=config.LOCAL_LLM_TEMPERATURE,
            max_tokens=config.LOCAL_LLM_MAX_TOKENS,
        )
        text = response.choices[0].message.content or ""
        print(f"[local_llm] <- {label} ({len(text)} characters)")
        return text

    except Exception as error:
        raise RuntimeError(
            f"Local LLM request failed during {label}: {error}. "
            f"Is LM Studio's server running at {config.LOCAL_LLM_URL}?"
        ) from error


# Timestamp of the most recent Gemini call, used to pace requests. Module-level
# because the limit applies to the API key as a whole, not to any one batch.
_last_gemini_call = 0.0


def _throttle_gemini():
    """
    Wait, if needed, so calls stay within the configured requests-per-minute.

    TRACE issues its batches back to back. Without pacing, a case large enough
    to need several batches exceeds the free tier's per-minute limit partway
    through and aborts an analysis that was otherwise succeeding.
    """
    global _last_gemini_call

    elapsed = time.time() - _last_gemini_call
    wait = config.GEMINI_SECONDS_BETWEEN - elapsed
    if wait > 0:
        time.sleep(wait)
    _last_gemini_call = time.time()


def _call_gemini(system_prompt, user_prompt, label):
    """
    Send one prompt to Google's Gemini API and return its raw text response.

    The Interactions API takes a single `input` string rather than the separate
    system and user roles the local path uses, so the two prompts are joined
    with a blank line. Their CONTENT and ORDER are unchanged, which keeps the
    two providers comparable.

    Failures are retried with exponential backoff, because the common cause is
    a per-minute rate limit rather than anything wrong with the request - the
    same call usually succeeds moments later. The underlying error is printed
    on every attempt so the real cause is visible in the console, instead of
    being hidden behind the HTTP 503 the API returns to the browser.

    A client is constructed per call rather than cached at import time. The
    cost is negligible against the model call itself, and it means editing the
    key in .env plus a server restart always takes effect - matching how every
    other setting in TRACE behaves.
    """
    from google import genai

    last_error = None

    for attempt in range(1, config.GEMINI_MAX_RETRIES + 1):
        _throttle_gemini()
        print(f"[gemini] -> {label}"
              + (f" (attempt {attempt})" if attempt > 1 else ""))

        try:
            client = genai.Client(api_key=config.GEMINI_API_KEY)
            interaction = client.interactions.create(
                model=f"models/{config.GEMINI_MODEL}",
                input=f"{system_prompt}\n\n{user_prompt}",
                generation_config={
                    "max_output_tokens": config.GEMINI_MAX_TOKENS,
                    "thinking_level":    config.GEMINI_THINKING_LEVEL,
                },
            )
            text = interaction.output_text or ""
            print(f"[gemini] <- {label} ({len(text)} characters)")
            return text

        except Exception as error:
            last_error = error
            # Printed rather than only raised, so the cause appears in the
            # server console even though FastAPI converts it to a bare 503.
            print(f"[gemini] !! {label} attempt {attempt} failed: "
                  f"{type(error).__name__}: {error}", flush=True)

            if attempt < config.GEMINI_MAX_RETRIES:
                backoff = config.GEMINI_SECONDS_BETWEEN * (2 ** attempt)
                print(f"[gemini]    retrying in {backoff:.0f}s", flush=True)
                time.sleep(backoff)

    raise RuntimeError(
        f"Gemini request failed during {label} after "
        f"{config.GEMINI_MAX_RETRIES} attempts: {last_error}. "
        f"If this is a rate limit, lower GEMINI_REQUESTS_PER_MIN in .env "
        f"(currently {config.GEMINI_REQUESTS_PER_MIN}/min)."
    ) from last_error


# ---------------------------------------------------------------------------
# STAGE 4 - Pass 1: initial metadata-only assessment
# ---------------------------------------------------------------------------

def run_pass1(rows):
    """
    Ask the model which entries look suspicious from metadata alone.

    Entries are sent in batches of LOCAL_LLM_BATCH_SIZE. The id given to the
    model is the row's index in `rows`, and the model echoes it back, so
    results map straight home with no offset arithmetic.

    Returns {row_index: {"score", "justification", "mitre"}} containing only
    the entries the model chose to flag. "mitre" is a single validated
    technique ID string, or "" when the model proposed none.
    """
    if not rows:
        return {}

    client = _require_client()
    system_prompt = ai_engine.build_pass1_system_prompt()
    batch_size = config.LOCAL_LLM_BATCH_SIZE
    flagged = {}

    for start in range(0, len(rows), batch_size):
        batch = rows[start:start + batch_size]
        batch_number = start // batch_size + 1

        entries = [
            ai_engine.format_pass1_entry(start + offset, row)
            for offset, row in enumerate(batch)
        ]

        raw_response = _call(
            client,
            system_prompt,
            ai_engine.PASS1_USER_TEMPLATE.format(entries="\n".join(entries)),
            f"pass 1 batch {batch_number}",
        )

        for item in ai_engine.extract_json_array(raw_response) or []:
            if not isinstance(item, dict):
                continue

            index = item.get("entry_id")
            if not isinstance(index, int) or not (0 <= index < len(rows)):
                continue          # model referenced an entry that does not exist

            # Validate the technique now so an invented ID never travels
            # further into the pipeline.
            proposed = str(item.get("mitre_technique", "")).strip()
            validated = mitre.validate([proposed]) if proposed else []

            flagged[index] = {
                "score":         ai_engine.clamp_score(item.get("severity_score")),
                "justification": str(item.get("justification", "")).strip(),
                "mitre":         validated[0] if validated else "",
            }

    print(f"[local_llm] pass 1 flagged {len(flagged)} of {len(rows)} entries")
    return flagged


# ---------------------------------------------------------------------------
# STAGE 5 - Pass 2: reconciliation with threat intel and correlation evidence
# ---------------------------------------------------------------------------

def run_pass2(candidates):
    """
    Ask the model for a final verdict, given all available evidence.

    `candidates` is a list of dicts, each containing:
        index          the row's index in the original rows list
        row            the parsed artifact row
        initial        that row's Pass 1 result, or None if it was not flagged
        intel_summary  curated antivirus evidence, or None
        correlation    cross-artifact execution evidence

    Every candidate gets a verdict, including ones the model decides are benign
    (scored low) - unlike Pass 1, which only returns what it flags.

    Returns {row_index: {"score", "justification", "mitre"}}.
    """
    if not candidates:
        return {}

    client = _require_client()
    system_prompt = ai_engine.build_pass2_system_prompt()
    verdicts = {}

    for start in range(0, len(candidates), PASS2_BATCH_SIZE):
        batch = candidates[start:start + PASS2_BATCH_SIZE]
        batch_number = start // PASS2_BATCH_SIZE + 1

        # The prompt id is the position within `candidates`, which is mapped
        # back to the real row index after the response is parsed.
        entries = [
            ai_engine.format_pass2_entry(
                start + offset,
                candidate["row"],
                candidate["initial"],
                candidate["intel_summary"],
                candidate["correlation"],
            )
            for offset, candidate in enumerate(batch)
        ]

        raw_response = _call(
            client,
            system_prompt,
            ai_engine.PASS2_USER_TEMPLATE.format(entries="\n".join(entries)),
            f"pass 2 batch {batch_number}",
        )

        for item in ai_engine.extract_json_array(raw_response) or []:
            if not isinstance(item, dict):
                continue

            position = item.get("entry_id")
            if not isinstance(position, int) or not (0 <= position < len(candidates)):
                continue

            candidate = candidates[position]

            # Validate again - Pass 2 is allowed to change the technique, so
            # its answer needs the same protection against invented IDs.
            proposed = str(item.get("mitre_technique", "")).strip()
            validated = mitre.validate([proposed]) if proposed else []

            # Fall back to the Pass 1 technique when Pass 2 returns none.
            technique = validated[0] if validated else ""
            if not technique and candidate["initial"]:
                technique = candidate["initial"].get("mitre", "")

            verdicts[candidate["index"]] = {
                "score":         ai_engine.clamp_score(item.get("final_score")),
                "justification": str(item.get("justification", "")).strip(),
                "mitre":         technique,
            }

    print(f"[local_llm] pass 2 returned verdicts for {len(verdicts)} "
          f"of {len(candidates)} candidates")
    return verdicts
