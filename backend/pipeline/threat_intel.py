from backend.pipeline import metadefender, otx, virustotal


def lookup_all(rows):
    """
    Query all three threat-intel sources for every unique hash in `rows`.

    De-duplicates hashes first, so a file appearing many times costs one
    lookup. Each source handles its own caching and rate limiting internally.

    Returns {"vt": {sha1: fields}, "md": {...}, "otx": {...},
             "hashes_checked": int}
    """
    hashes = sorted({row["sha1"] for row in rows if row.get("sha1")})

    if not hashes:
        print("[threat_intel] no hashes to check "
              "(only Amcache records file hashes)")
        return {"vt": {}, "md": {}, "otx": {}, "hashes_checked": 0}

    print(f"[threat_intel] looking up {len(hashes)} unique hashes "
          f"across VirusTotal, MetaDefender and OTX")

    return {
        "vt":             virustotal.enrich(hashes),
        "md":             metadefender.enrich(hashes),
        "otx":            otx.enrich(hashes),
        "hashes_checked": len(hashes),
    }


def fields_for(sha1, intel):
    """
    Return every threat-intel field for one hash, with safe defaults.

    Merging each source's EMPTY template first guarantees that all vt_/md_/otx_
    keys always exist, so the report and CSV writers never hit a missing key
    for a file that had no hash or was never found.
    """
    if not sha1:
        return {**virustotal.EMPTY, **metadefender.EMPTY, **otx.EMPTY}

    return {
        **virustotal.EMPTY,   **intel["vt"].get(sha1, {}),
        **metadefender.EMPTY, **intel["md"].get(sha1, {}),
        **otx.EMPTY,          **intel["otx"].get(sha1, {}),
    }


def has_signal(fields):
    """
    True when any source reported something worth a second look.

    Deliberately sensitive: a single detection, or one OTX pulse, is enough.
    This is what guarantees a hash with real-world detections always reaches
    the AI reconciliation pass even when the first AI pass ignored it.
    """
    return bool(
        fields.get("vt_detections", 0) > 0
        or fields.get("md_detections", 0) > 0
        or fields.get("otx_pulse_count", 0) > 0
        or fields.get("vt_confirmed_malware")
    )


def is_confirmed_malware(fields, threshold):
    """
    True only for an unambiguous malicious verdict from real AV engines.

    A single engine flagging a file is usually a false positive, so the bar is
    `threshold` independent engines (default 5). This drives the hard scoring
    floor in scoring.py - the one place a machine verdict overrides the AI.
    """
    return bool(
        fields.get("vt_confirmed_malware")
        or fields.get("vt_detections", 0) >= threshold
        or fields.get("md_detections", 0) >= threshold
    )


def summarise_for_ai(fields):
    """
    Reduce raw threat-intel fields to the evidence the AI actually needs.

    The full VirusTotal payload has dozens of fields (PE headers, TRID data,
    vhash, submission history) that would consume the model's limited context
    without improving its judgement. This keeps detection counts, the malware
    family, threat category, a few real engine verdicts, and OTX pulse data -
    the parts an analyst would actually read.

    Returns None when no source has anything to say, so the caller can omit the
    section from the prompt entirely rather than sending empty scaffolding.
    """
    summary = {}

    # --- VirusTotal ------------------------------------------------------
    if fields.get("vt_checked"):
        if fields.get("vt_found"):
            summary["virustotal"] = {
                "detections":     f"{fields.get('vt_detections', 0)} of "
                                  f"{fields.get('vt_total_engines', 0)} engines",
                "verdict":        fields.get("vt_verdict_label", "UNKNOWN"),
                "malware_family": fields.get("vt_malware_family", "") or "none reported",
                "threat_category": fields.get("vt_popular_threat_category", "") or "none",
                # A few actual engine names and what they called it - far more
                # informative to the model than a bare number.
                "sample_engine_verdicts": [
                    f"{engine.get('engine', '?')}: {engine.get('result', '?')}"
                    for engine in fields.get("vt_sample_engines", [])[:5]
                ],
                "first_seen": fields.get("vt_first_seen", "") or "unknown",
            }
        else:
            # Explicitly stated, because "VirusTotal has never seen this file"
            # is itself meaningful - novel or targeted payloads look like this.
            summary["virustotal"] = {"result": "hash not found in VirusTotal"}

    # --- MetaDefender ----------------------------------------------------
    if fields.get("md_checked"):
        if fields.get("md_found"):
            summary["metadefender"] = {
                "detections": f"{fields.get('md_detections', 0)} of "
                              f"{fields.get('md_total_engines', 0)} engines",
                "verdict":    fields.get("md_verdict_label", "UNKNOWN"),
                "threat":     fields.get("md_threat", "") or "none reported",
            }
        else:
            summary["metadefender"] = {"result": "hash not found in MetaDefender"}

    # --- AlienVault OTX --------------------------------------------------
    pulse_count = fields.get("otx_pulse_count", 0)
    if fields.get("otx_checked") and pulse_count:
        summary["alienvault_otx"] = {
            "pulses":           pulse_count,
            "malware_families": fields.get("otx_malware_families", [])[:3],
            "tags":             fields.get("otx_tags", [])[:5],
        }

    return summary or None
