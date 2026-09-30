import json
import time
import logging

import requests

from backend import config

log = logging.getLogger(__name__)

_cache: dict | None = None


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

def _load_cache() -> dict:
    global _cache
    if _cache is None:
        if config.METADEFENDER_CACHE_FILE.exists():
            try:
                _cache = json.loads(config.METADEFENDER_CACHE_FILE.read_text())
            except (json.JSONDecodeError, OSError):
                _cache = {}
        else:
            _cache = {}
    return _cache


def _save_cache() -> None:
    if _cache is not None:
        config.METADEFENDER_CACHE_FILE.write_text(json.dumps(_cache, indent=2))


# ---------------------------------------------------------------------------
# Response parser
# ---------------------------------------------------------------------------

def _parse_md_response(data: dict) -> dict:
    """Reduce the MetaDefender v4 hash lookup payload to the fields TRACE uses."""

    scan_results = data.get("scan_results", {})
    scan_details = scan_results.get("scan_details", {})

    malicious   = 0
    suspicious  = 0
    total       = len(scan_details)
    sample_engines: list[dict] = []

    for engine_name, detail in scan_details.items():
        threat = detail.get("threat_found", "")
        result = detail.get("scan_result_i", -1)
        # MetaDefender: 1 = infected/known, 2 = suspicious, 0 = clean
        if result == 1 and threat:
            malicious += 1
            if len(sample_engines) < 5:
                sample_engines.append({"engine": engine_name, "result": threat})
        elif result == 2:
            suspicious += 1
            if len(sample_engines) < 5:
                sample_engines.append({"engine": engine_name, "result": threat or "Suspicious"})

    detections = malicious + suspicious
    ratio      = round(detections / total, 4) if total else 0.0

    # Overall threat name from top-level classification
    threat_name = scan_results.get("scan_all_result_a", "") or ""

    # File info
    file_info = data.get("file_info", {})
    sha256     = file_info.get("sha256", "")
    permalink  = f"https://metadefender.opswat.com/results/file/{sha256}/regular/overview" if sha256 else ""

    scan_date = scan_results.get("start_time", "")

    if detections >= 5:
        verdict_label = "CONFIRMED_MALWARE"
    elif detections >= 2:
        verdict_label = "LIKELY_MALWARE"
    elif detections == 1:
        verdict_label = "LIKELY_CLEAN"
    else:
        verdict_label = "CLEAN"

    return {
        "md_checked":        True,
        "md_found":          True,
        "md_detections":     detections,
        "md_total_engines":  total,
        "md_detection_ratio": ratio,
        "md_threat":         threat_name,
        "md_sample_engines": sample_engines,
        "md_scan_date":      scan_date,
        "md_permalink":      permalink,
        "md_verdict_label":  verdict_label,
    }


# ---------------------------------------------------------------------------
# Blank result templates
# ---------------------------------------------------------------------------

EMPTY = {
    "md_checked": False, "md_found": False,
    "md_detections": 0,  "md_total_engines": 0,
    "md_detection_ratio": 0.0, "md_threat": "",
    "md_sample_engines": [], "md_scan_date": "",
    "md_permalink": "", "md_verdict_label": "UNKNOWN",
}

NOT_FOUND = {**EMPTY, "md_checked": True, "md_found": False}


# ---------------------------------------------------------------------------
# Single live lookup
# ---------------------------------------------------------------------------

def _lookup_one(sha1: str):
    """
    Look up one hash. Returns the parsed fields, or None on a network failure.

    None is deliberately distinct from an empty result: "MetaDefender is
    unreachable" is not the same fact as "MetaDefender has never seen this
    hash". The caller uses that difference to avoid caching a transient outage
    as a permanent verdict, and to abandon the source once it is clearly down.
    """
    url     = f"{config.METADEFENDER_BASE_URL}/{sha1}"
    headers = {"apikey": config.METADEFENDER_API_KEY}
    backoff = config.METADEFENDER_SECONDS_BETWEEN

    for _ in range(4):
        try:
            resp = requests.get(url, headers=headers, timeout=config.TI_TIMEOUT)
        except requests.RequestException as e:
            log.error("[metadefender] network error for %s: %s", sha1[:12], e)
            print(f"[metadefender] network error for {sha1[:12]}: {e}")
            return None                      # network failure - do NOT cache

        if resp.status_code == 200:
            data   = resp.json()
            # MetaDefender returns {"error": {...}} for unknown hashes
            if "error" in data:
                log.debug("[metadefender] %s not found.", sha1[:12])
                return dict(NOT_FOUND)
            result = _parse_md_response(data)
            log.info("[metadefender] %s → %d/%d [%s] %s",
                     sha1[:12], result["md_detections"], result["md_total_engines"],
                     result["md_verdict_label"], result["md_threat"])
            return result

        if resp.status_code == 404:
            log.debug("[metadefender] %s not found.", sha1[:12])
            return dict(NOT_FOUND)

        if resp.status_code == 429:
            log.warning("[metadefender] 429 rate-limited, backing off %.0fs", backoff)
            time.sleep(min(backoff, config.METADEFENDER_MAX_BACKOFF))
            backoff = min(backoff * 2, config.METADEFENDER_MAX_BACKOFF)
            continue

        if resp.status_code in (401, 403):
            log.error("[metadefender] auth error - check METADEFENDER_API_KEY.")
            print("[metadefender] auth error - check METADEFENDER_API_KEY.")
            return None                      # config problem, not a verdict

        log.warning("[metadefender] HTTP %d for %s", resp.status_code, sha1[:12])
        return None

    return None                              # retries exhausted


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def enrich(hashes: list[str]) -> dict:
    """
    Look up a list of SHA-1 hashes against MetaDefender Cloud.

    De-duplicates, serves from cache where possible, and respects the rate
    limit.

    Two safeguards keep a failing service from ruining a run:

      - A network failure is never written to the cache. Caching it would
        record "we checked and found nothing" for a hash that was never
        actually checked, and that mistake would persist across every future
        run of the case.
      - After TI_MAX_CONSECUTIVE_FAILURES failures in a row the source is
        abandoned for the rest of this run, rather than paying the full
        timeout for every remaining hash.
    """
    unique = [h for h in {h.strip() for h in hashes if h and h.strip()}]

    if not config.METADEFENDER_API_KEY:
        if unique:
            log.info("[metadefender] skipped (no key) for %d hashes", len(unique))
            print(f"[metadefender] skipped (no API key) for {len(unique)} hashes")
        return {h: dict(EMPTY) for h in unique}

    cache = _load_cache()
    to_fetch = [h for h in unique if h not in cache]
    print(f"[metadefender] {len(unique)} unique hashes: "
          f"{len(unique) - len(to_fetch)} cached, {len(to_fetch)} to fetch")

    consecutive_failures = 0

    for index, sha1 in enumerate(to_fetch):
        result = _lookup_one(sha1)

        if result is None:
            consecutive_failures += 1
            if consecutive_failures >= config.TI_MAX_CONSECUTIVE_FAILURES:
                remaining = len(to_fetch) - index - 1
                print(f"[metadefender] MetaDefender has failed more than "
                      f"{config.TI_MAX_CONSECUTIVE_FAILURES} times, proceeding "
                      f"without MetaDefender data. {remaining} hash(es) were not "
                      f"looked up in this run.", flush=True)
                break
        else:
            consecutive_failures = 0
            cache[sha1] = result             # only successful lookups are cached
            _save_cache()

        if index < len(to_fetch) - 1:
            time.sleep(config.METADEFENDER_SECONDS_BETWEEN)

    return {h: cache.get(h, dict(EMPTY)) for h in unique}
