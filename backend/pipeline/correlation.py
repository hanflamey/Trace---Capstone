def executable_stem(name_or_path):
    """
    Reduce a file path to the key used for cross-artifact matching.

    The key is  "<parent_directory>:<filename_without_extension>"  so that the
    same binary seen by multiple artifacts at the SAME location merges
    correctly, while the same filename at ANY different location gets its own
    separate key and is assessed independently.

    Examples:
        C:\\Windows\\System32\\svchost.exe (Amcache)
        C:\\Windows\\System32\\svchost.exe (ShimCache)
        -> both become "c:\\windows\\system32:svchost"  -> MERGED correctly

        C:\\Windows\\System32\\svchost.exe
        C:\\Users\\isaac\\Downloads\\svchost.exe
        -> "c:\\windows\\system32:svchost"
        -> "c:\\users\\isaac\\downloads:svchost"        -> SEPARATE correctly

        C:\\Windows\\Temp\\test_meterpreter.exe
        C:\\Users\\isaac\\Downloads\\test_meterpreter.exe
        -> "c:\\windows\\temp:test_meterpreter"
        -> "c:\\users\\isaac\\downloads:test_meterpreter" -> SEPARATE correctly

    When only a bare filename is supplied with no path information, the
    directory portion defaults to "unknown" so matching still works across
    artifacts that record only a name.
    """
    raw = (name_or_path or "").replace("/", "\\").rstrip("\\").lower()

    parts = raw.rsplit("\\", 1)
    if len(parts) == 2:
        directory = parts[0]
        leaf      = parts[1]
    else:
        directory = "unknown"
        leaf      = parts[0]

    stem = leaf.rsplit(".", 1)[0] if "." in leaf else leaf

    if not stem:
        return ""

    return f"{directory}:{stem}"


def build_index(rows):
    """
    Group every parsed row by executable stem.

    Returns {stem: evidence} where evidence collects what all three artifacts
    collectively know about that one executable:

        sources        which artifacts it appeared in
        executed       True if any artifact proves it ran
        run_count      highest run count seen (Prefetch)
        run_times      merged execution timestamps (Prefetch)
        paths          every distinct path it was recorded under
        files_loaded   files/DLLs loaded at run time (Prefetch)

    Built once over all rows, then queried per finding by evidence_for().

    Because executable_stem now keys on the full parent directory plus the
    filename, a legitimate system binary and a same-named file anywhere else
    on disk produce different keys and are indexed separately. Each is then
    assessed by the AI on its own merits.
    """
    index = {}

    for row in rows:
        stem = executable_stem(row.get("full_path") or row.get("name", ""))
        if not stem:
            continue

        evidence = index.setdefault(stem, {
            "sources":      set(),
            "executed":     False,
            "run_count":    0,
            "run_times":    [],
            "paths":        set(),
            "files_loaded": [],
        })

        evidence["sources"].add(row.get("source", ""))

        if row.get("full_path"):
            evidence["paths"].add(row["full_path"])

        # A Prefetch row exists only because the program ran; ShimCache states
        # it explicitly. Either is proof of execution.
        if row.get("source") == "prefetch" or row.get("executed") is True:
            evidence["executed"] = True

        if row.get("run_count"):
            evidence["run_count"] = max(evidence["run_count"], row["run_count"])

        for timestamp in row.get("run_history_utc", []):
            if timestamp not in evidence["run_times"]:
                evidence["run_times"].append(timestamp)

        # Keep a bounded sample of loaded files - enough to spot DLL
        # sideloading without flooding the AI prompt later.
        for loaded in row.get("files_loaded", [])[:20]:
            if loaded not in evidence["files_loaded"]:
                evidence["files_loaded"].append(loaded)

    print(f"[correlation] indexed {len(index)} unique executables")
    return index


def evidence_for(row, index):
    """
    Return the correlation evidence for one row, as plain readable facts.

    The output feeds the AI reconciliation prompt (Stage 5), so it is phrased
    as short statements a human would write rather than as scores. Deciding
    what the evidence is worth is the model's job, not this module's.

    Returns a dict with:
        sources      sorted list of artifacts the executable appeared in
        executed     whether execution is proven
        run_count    highest observed run count
        run_times    up to 5 execution timestamps
        statements   human-readable evidence lines for the prompt
    """
    evidence = index.get(
        executable_stem(row.get("full_path") or row.get("name", ""))
    )

    if not evidence:
        return {"sources": [], "executed": False, "run_count": 0,
                "run_times": [], "statements": []}

    sources = sorted(source for source in evidence["sources"] if source)
    statements = []

    # How many independent artifacts recorded this executable.
    if len(sources) >= 3:
        statements.append("Recorded in all three artifacts "
                          "(Amcache, Prefetch, ShimCache)")
    elif len(sources) == 2:
        statements.append(f"Recorded in {' and '.join(sources)}")
    else:
        statements.append(f"Recorded only in {sources[0]}" if sources else "")

    # Execution proof, and how strong it is.
    if evidence["executed"]:
        if "prefetch" in sources:
            statements.append("Execution PROVEN by Prefetch")
        else:
            statements.append("Execution proven by ShimCache (Executed=Yes)")
    else:
        statements.append("No execution evidence - presence on disk only")

    # Repeated execution is a stronger signal than a single run.
    if evidence["run_count"] >= 5:
        statements.append(f"Executed {evidence['run_count']} times (repeated use)")
    elif evidence["run_count"]:
        statements.append(f"Executed {evidence['run_count']} time(s)")

    if evidence["run_times"]:
        shown = evidence["run_times"][:3]
        statements.append("Execution times: " + ", ".join(shown)
                          + (" ..." if len(evidence["run_times"]) > 3 else ""))

    # Multiple distinct paths for one name can indicate a copied or relocated
    # binary, which is worth the analyst's attention.
    if len(evidence["paths"]) > 1:
        statements.append(f"Seen at {len(evidence['paths'])} different paths")

    return {
        "sources":    sources,
        "executed":   evidence["executed"],
        "run_count":  evidence["run_count"],
        "run_times":  evidence["run_times"][:5],
        "statements": [line for line in statements if line],
    }


def collapse_to_executables(rows, index):
    """
    Reduce many artifact rows to ONE enriched row per unique executable.

    This runs before the AI, and it solves two problems at once.

    1. METADATA POVERTY. Prefetch and ShimCache record no publisher, product
       name, version or OS-component flag - only a name and a path. Asking the
       model to judge "svchost.exe" from a bare filename invites false
       positives. When Amcache saw the same executable, it DOES have that
       metadata, so it is copied onto the merged row here.

    2. REPEATED JUDGEMENT. Previously a file present in all three artifacts was
       assessed three separate times and the highest score won - three
       independent chances for the model to be wrong about one file. Now each
       executable is judged exactly once, which also cuts LLM calls sharply.

    The Amcache row is preferred as the base because it is the only one
    carrying a SHA-1 (needed for threat intel) plus signing metadata. Execution
    evidence from the other artifacts is merged in on top.

    NOTE ON KEYING. Because executable_stem now keys on the full parent
    directory, a legitimate system binary and a same-named masquerading copy
    anywhere else on disk produce DIFFERENT keys and are collapsed separately —
    regardless of what directory they are in. The masquerading copy is never
    hidden behind the legitimate entry's metadata.
    """
    # Rank of each source when choosing which row to build from: Amcache first
    # (hash + metadata), then Prefetch (execution proof), then ShimCache.
    source_priority = {"amcache": 0, "prefetch": 1, "shimcache": 2}

    grouped = {}
    for row in rows:
        # Use full_path first so the directory portion of the key is computed
        # from the richest location information available for this row.
        stem = executable_stem(row.get("full_path") or row.get("name", ""))
        if not stem:
            continue
        grouped.setdefault(stem, []).append(row)

    collapsed = []
    for stem, group in grouped.items():
        # Build from the highest-priority artifact available.
        group.sort(key=lambda r: source_priority.get(r.get("source", ""), 9))
        merged = dict(group[0])

        # Record every artifact this executable appeared in.
        merged["seen_in_sources"] = sorted({r["source"] for r in group})

        # Back-fill identity metadata from whichever row actually has it.
        # In practice this copies Amcache's publisher/product/version onto a
        # Prefetch or ShimCache row, so the model is never judging blind.
        for field in ("sha1", "product_name", "version", "description",
                      "original_file_name", "link_date_utc", "publisher"):
            if not merged.get(field):
                for other in group:
                    if other.get(field):
                        merged[field] = other[field]
                        break

        # is_os_component is a boolean, so it needs its own merge: if ANY
        # artifact says this is a signed OS component, treat it as one.
        merged["is_os_component"] = any(r.get("is_os_component") for r in group)

        # Likewise for whether publisher data was available at all. If any
        # source CSV carried a Publisher column, an empty value is meaningful
        # (unsigned); if none did, an empty value means nothing was recorded.
        merged["publisher_recorded"] = any(r.get("publisher_recorded") for r in group)

        # A full path from any artifact beats an empty one.
        if not merged.get("full_path"):
            for other in group:
                if other.get("full_path"):
                    merged["full_path"] = other["full_path"]
                    break

        # Merge execution evidence across the group.
        merged["run_count"] = max((r.get("run_count") or 0) for r in group)
        merged["executed"] = any(r.get("executed") is True for r in group)

        run_times = []
        for other in group:
            for timestamp in other.get("run_history_utc", []):
                if timestamp not in run_times:
                    run_times.append(timestamp)
        merged["run_history_utc"] = run_times

        # Keep the earliest known timestamp so the timeline stays honest.
        timestamps = sorted(r["timestamp_utc"] for r in group
                            if r.get("timestamp_utc"))
        if timestamps:
            merged["timestamp_utc"] = timestamps[0]

        collapsed.append(merged)

    print(f"[correlation] collapsed {len(rows)} artifact rows into "
          f"{len(collapsed)} unique executables")
    return collapsed


def summary(index):
    """
    Dataset-level correlation statistics for the report metadata.

    Reports how many unique executables were seen, how many appeared in more
    than one artifact, and how many have proven execution.
    """
    multi_artifact = sum(
        1 for evidence in index.values()
        if len([source for source in evidence["sources"] if source]) >= 2
    )
    executed = sum(1 for evidence in index.values() if evidence["executed"])

    return {
        "unique_executables":         len(index),
        "seen_in_multiple_artifacts": multi_artifact,
        "execution_confirmed":        executed,
    }