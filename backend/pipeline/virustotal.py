import json
import time
import logging

import requests

from backend import config

log = logging.getLogger(__name__)

_cache: dict | None = None


# ---------------------------------------------------------------------------
# Cache helpers (unchanged from original)
# ---------------------------------------------------------------------------

def _load_cache() -> dict:
    global _cache
    if _cache is None:
        if config.VT_CACHE_FILE.exists():
            try:
                _cache = json.loads(config.VT_CACHE_FILE.read_text())
            except (json.JSONDecodeError, OSError):
                _cache = {}
        else:
            _cache = {}
    return _cache


def _save_cache() -> None:
    if _cache is not None:
        config.VT_CACHE_FILE.write_text(json.dumps(_cache, indent=2))


# ---------------------------------------------------------------------------
# Response parser — richer than the original
# ---------------------------------------------------------------------------

def _parse_vt_response(data: dict) -> dict:
    """Reduce the VT v3 /files/{hash} payload to the fields TRACE uses."""
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    malicious   = int(stats.get("malicious",   0))
    suspicious  = int(stats.get("suspicious",  0))
    detections  = malicious + suspicious
    total       = sum(int(v) for v in stats.values()) if stats else 0
    ratio       = round(detections / total, 4) if total else 0.0

    # ── classification ───────────────────────────────────────────────────
    pop_threat  = attrs.get("popular_threat_classification", {})

    # suggested_threat_label is the most human-readable single string
    family = attrs.get("popular_threat_classification", {}).get("suggested_threat_label", "")
    if not family:
        names = pop_threat.get("popular_threat_name", [])
        if names:
            family = names[0].get("value", "")

    categories = pop_threat.get("popular_threat_category", [])
    threat_category = categories[0].get("value", "") if categories else ""

    type_tags = attrs.get("type_tags", [])

    # ── timeline ─────────────────────────────────────────────────────────
    def _ts(key: str) -> str:
        v = attrs.get(key)
        if not v:
            return ""
        try:
            return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(v)))
        except (ValueError, TypeError):
            return ""

    first_seen      = _ts("first_submission_date")
    last_seen       = _ts("last_submission_date")
    times_submitted = attrs.get("times_submitted", 0)

    # ── sample of flagging engines (up to 5) ─────────────────────────────
    engine_results = attrs.get("last_analysis_results", {})
    sample_engines = [
        {"engine": name, "result": info.get("result") or info.get("category", "")}
        for name, info in engine_results.items()
        if info.get("category") in ("malicious", "suspicious") and info.get("result")
    ][:5]

    # ── permalink (requires sha256) ───────────────────────────────────────
    sha256    = attrs.get("sha256", "")
    permalink = f"https://www.virustotal.com/gui/file/{sha256}" if sha256 else ""

    # ── false-positive verdict ────────────────────────────────────────────
    if detections >= 5:
        verdict_label     = "CONFIRMED_MALWARE"
        confirmed_malware = True
    elif detections >= 2:
        verdict_label     = "LIKELY_MALWARE"
        confirmed_malware = False
    elif detections == 1:
        verdict_label     = "LIKELY_CLEAN"      # single engine = likely FP
        confirmed_malware = False
    else:
        verdict_label     = "CLEAN"
        confirmed_malware = False

    return {
        # core fields (kept for backwards-compat with existing pipeline code)
        "vt_checked":       True,
        "vt_found":         True,
        "vt_detections":    detections,
        "vt_total_engines": total,
        "vt_malware_family": family,
        "vt_first_seen":    first_seen,
        "vt_last_seen":     last_seen,
        # new enriched fields
        "vt_detection_ratio":         ratio,
        "vt_popular_threat_category": threat_category,
        "vt_type_tags":               type_tags,
        "vt_times_submitted":         times_submitted,
        "vt_sample_engines":          sample_engines,
        "vt_permalink":               permalink,
        "vt_confirmed_malware":       confirmed_malware,
        "vt_verdict_label":           verdict_label,
    }


# ---------------------------------------------------------------------------
# Blank result templates
# ---------------------------------------------------------------------------

EMPTY = {
    "vt_checked": False, "vt_found": False,
    "vt_detections": 0,  "vt_total_engines": 0,
    "vt_malware_family": "", "vt_first_seen": "", "vt_last_seen": "",
    # enriched fields — safe defaults so the frontend never KeyErrors
    "vt_detection_ratio": 0.0, "vt_popular_threat_category": "",
    "vt_type_tags": [], "vt_times_submitted": 0, "vt_sample_engines": [],
    "vt_permalink": "", "vt_confirmed_malware": False,
    "vt_verdict_label": "UNKNOWN",
}

# Hash exists in VT but zero detections.
NOT_FOUND = {
    **EMPTY,
    "vt_checked": True,
    "vt_found":   False,
    "vt_verdict_label": "UNKNOWN",
}


# ---------------------------------------------------------------------------
# Single live lookup (unchanged retry/backoff logic from original)
# ---------------------------------------------------------------------------

def _lookup_one(sha1: str):
    """
    Look up one hash. Returns the parsed fields, or None on a network failure.

    None is deliberately distinct from an empty result: "VirusTotal is
    unreachable" is not the same fact as "VirusTotal has never seen this hash".
    The caller uses that difference to avoid caching a transient outage as a
    permanent verdict, and to abandon the source once it is clearly down.
    """
    headers = {"x-apikey": config.VT_API_KEY}
    url     = config.VT_BASE_URL + sha1
    backoff = config.VT_SECONDS_BETWEEN

    for _ in range(4):
        try:
            resp = requests.get(url, headers=headers, timeout=config.TI_TIMEOUT)
        except requests.RequestException as e:
            log.error("[virustotal] network error for %s: %s", sha1[:12], e)
            print(f"[virustotal] network error for {sha1[:12]}: {e}")
            return None                      # network failure - do NOT cache

        if resp.status_code == 200:
            result = _parse_vt_response(resp.json())
            log.info(
                "[virustotal] %s → %d/%d [%s] %s",
                sha1[:12],
                result["vt_detections"], result["vt_total_engines"],
                result["vt_verdict_label"], result["vt_malware_family"],
            )
            return result

        if resp.status_code == 404:
            log.debug("[virustotal] hash %s not found in VT database.", sha1[:12])
            return dict(NOT_FOUND)

        if resp.status_code == 429:
            retry_after = float(resp.headers.get("Retry-After", backoff))
            wait = min(retry_after, config.VT_MAX_BACKOFF)
            log.warning("[virustotal] 429 rate-limited, backing off %.0fs", wait)
            time.sleep(wait)
            backoff = min(backoff * 2, config.VT_MAX_BACKOFF)
            continue

        if resp.status_code in (401, 403):
            log.error("[virustotal] auth error - check VT_API_KEY.")
            print("[virustotal] auth error - check VT_API_KEY.")
            return None                      # config problem, not a verdict

        log.warning("[virustotal] unexpected status %d for %s", resp.status_code, sha1[:12])
        return None

    return None                              # retries exhausted


# ---------------------------------------------------------------------------
# Public API — enrich() is unchanged; enrich_findings() is new
# ---------------------------------------------------------------------------

def enrich(hashes: list[str]) -> dict:
    """
    Look up a list of SHA-1 hashes against VirusTotal.

    De-duplicates, serves from cache where possible, and respects the free-tier
    rate limit on the remaining live calls.

    Two safeguards keep a failing service from ruining a run:

      - A network failure is never written to the cache. Caching it would
        record "we checked and found nothing" for a hash that was never
        actually checked, and that mistake would persist across every future
        run of the case.
      - After TI_MAX_CONSECUTIVE_FAILURES failures in a row the source is
        abandoned for the rest of this run. At the free tier's 15 seconds per
        request, an unreachable service otherwise stalls the analysis for
        minutes per remaining hash.
    """
    unique = [h for h in {h.strip() for h in hashes if h and h.strip()}]

    if not config.VT_API_KEY:
        if unique:
            log.info("[virustotal] skipped (no VT_API_KEY) for %d hashes", len(unique))
            print(f"[virustotal] skipped (no VT_API_KEY) for {len(unique)} hashes")
        return {h: dict(EMPTY) for h in unique}

    cache = _load_cache()
    to_fetch = [h for h in unique if h not in cache]
    print(f"[virustotal] {len(unique)} unique hashes: "
          f"{len(unique) - len(to_fetch)} cached, {len(to_fetch)} to fetch")

    consecutive_failures = 0

    for index, sha1 in enumerate(to_fetch):
        result = _lookup_one(sha1)

        if result is None:
            consecutive_failures += 1
            if consecutive_failures >= config.TI_MAX_CONSECUTIVE_FAILURES:
                remaining = len(to_fetch) - index - 1
                print(f"[virustotal] VirusTotal has failed more than "
                      f"{config.TI_MAX_CONSECUTIVE_FAILURES} times, proceeding "
                      f"without VirusTotal data. {remaining} hash(es) were not "
                      f"looked up in this run.", flush=True)
                break
        else:
            consecutive_failures = 0
            cache[sha1] = result             # only successful lookups are cached
            _save_cache()

        if index < len(to_fetch) - 1:
            time.sleep(config.VT_SECONDS_BETWEEN)

    return {h: cache.get(h, dict(EMPTY)) for h in unique}
