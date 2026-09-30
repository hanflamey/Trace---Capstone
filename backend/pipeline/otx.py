import json
import time

import requests

from backend import config

_cache: dict | None = None


def _load_cache() -> dict:
    global _cache
    if _cache is None:
        if config.OTX_CACHE_FILE.exists():
            try:
                _cache = json.loads(config.OTX_CACHE_FILE.read_text())
            except (json.JSONDecodeError, OSError):
                _cache = {}
        else:
            _cache = {}
    return _cache


def _save_cache() -> None:
    if _cache is not None:
        config.OTX_CACHE_FILE.write_text(json.dumps(_cache, indent=2))


EMPTY = {
    "otx_checked": False,
    "otx_pulse_count": 0,
    "otx_threat_labels": [],
    "otx_malware_families": [],
    "otx_tags": [],
}


def _parse_otx_response(data: dict) -> dict:
    """Reduce the OTX general response to the fields TRACE uses."""
    pulse_info = data.get("pulse_info", {})
    pulse_count = int(pulse_info.get("count", 0))

    # Collect unique threat labels from related pulses
    threat_labels: list[str] = []
    malware_families: list[str] = []
    tags: list[str] = []

    for pulse in pulse_info.get("pulses", []):
        # Pulse-level tags
        for t in pulse.get("tags", []):
            if t and t not in tags:
                tags.append(t)
        # Malware families
        for mf in pulse.get("malware_families", []):
            name = mf.get("display_name") or mf.get("id", "")
            if name and name not in malware_families:
                malware_families.append(name)
        # Threat labels from adversary / attack ids
        for atk in pulse.get("attack_ids", []):
            label = atk.get("display_name", "")
            if label and label not in threat_labels:
                threat_labels.append(label)

    return {
        "otx_checked": True,
        "otx_pulse_count": pulse_count,
        "otx_threat_labels": threat_labels[:10],   # cap for readability
        "otx_malware_families": malware_families[:5],
        "otx_tags": tags[:10],
    }


def _lookup_one(sha1: str):
    """
    Look up one hash. Returns the parsed fields, or None on a network failure.

    None is deliberately distinct from an empty result: "OTX is unreachable" is
    not the same fact as "OTX has never seen this hash". The caller uses that
    difference to avoid caching a transient outage as a permanent verdict, and
    to abandon the source once it is clearly down.
    """
    url = f"{config.OTX_BASE_URL}{sha1}/general"
    headers = {"X-OTX-API-KEY": config.OTX_API_KEY}
    backoff = config.OTX_SECONDS_BETWEEN

    for _ in range(4):
        try:
            resp = requests.get(url, headers=headers, timeout=config.TI_TIMEOUT)
        except requests.RequestException as error:
            print(f"[otx] network error for {sha1[:12]}: {error}")
            return None                      # network failure - do NOT cache

        if resp.status_code == 200:
            return _parse_otx_response(resp.json())

        if resp.status_code == 404:
            result = dict(EMPTY)
            result["otx_checked"] = True     # checked - just unknown to OTX
            return result

        if resp.status_code == 429:
            print(f"[otx] 429 rate-limited, backing off {backoff:.0f}s")
            time.sleep(backoff)
            backoff = min(backoff * 2, config.OTX_MAX_BACKOFF)
            continue

        if resp.status_code in (401, 403):
            print("[otx] auth error - check OTX_API_KEY. Skipping enrichment.")
            return None                      # config problem, not a verdict

        print(f"[otx] unexpected status {resp.status_code} for {sha1[:12]}")
        return None

    return None                              # retries exhausted


def enrich(hashes: list[str]) -> dict:
    """
    Look up a list of SHA-1 hashes against AlienVault OTX.

    De-duplicates, serves from cache where possible, and paces live calls.

    Two safeguards keep a failing service from ruining a run:

      - A network failure is never written to the cache. Caching it would
        record "we checked and found nothing" for a hash that was never
        actually checked, and the mistake would persist across every future
        run of the case.
      - After TI_MAX_CONSECUTIVE_FAILURES failures in a row the source is
        abandoned for the rest of this run. An unreachable service otherwise
        costs the full timeout for every remaining hash.
    """
    unique = [h for h in {h.strip() for h in hashes if h and h.strip()}]

    if not config.OTX_API_KEY:
        if unique:
            print(f"[otx] skipped (no OTX_API_KEY) for {len(unique)} hashes")
        return {h: dict(EMPTY) for h in unique}

    cache = _load_cache()
    to_fetch = [h for h in unique if h not in cache]
    print(f"[otx] {len(unique)} unique hashes: "
          f"{len(unique) - len(to_fetch)} cached, {len(to_fetch)} to fetch")

    consecutive_failures = 0
    abandoned = False

    for index, sha1 in enumerate(to_fetch):
        result = _lookup_one(sha1)

        if result is None:
            consecutive_failures += 1
            if consecutive_failures >= config.TI_MAX_CONSECUTIVE_FAILURES:
                remaining = len(to_fetch) - index - 1
                print(f"[otx] OTX has failed more than "
                      f"{config.TI_MAX_CONSECUTIVE_FAILURES} times, proceeding "
                      f"without OTX data. {remaining} hash(es) were not "
                      f"looked up in this run.", flush=True)
                abandoned = True
                break
        else:
            consecutive_failures = 0
            cache[sha1] = result             # only successful lookups are cached
            _save_cache()

        if index < len(to_fetch) - 1:
            time.sleep(config.OTX_SECONDS_BETWEEN)

    if abandoned:
        print("[otx] those hashes stay uncached, so they will be retried on "
              "the next run once OTX is reachable again.", flush=True)

    return {h: cache.get(h, dict(EMPTY)) for h in unique}
