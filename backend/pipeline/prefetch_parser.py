import re

import pandas as pd
from dateutil import parser as date_parser
from datetime import timezone


# Internal field -> possible PECmd column names, resolved case-insensitively.
COLUMN_ALIASES = {
    "executable_name": ["ExecutableName"],
    "run_count":       ["RunCount"],
    "last_run":        ["LastRun"],
    "prefetch_hash":   ["Hash"],
    "files_loaded":    ["FilesLoaded"],
    "directories":     ["Directories"],
    "source_filename": ["SourceFilename", "SourceFile"],
    "source_created":  ["SourceCreated"],
    "source_modified": ["SourceModified"],
    "volume_name":     ["Volume0Name", "VolumeName"],
    "volume_serial":   ["Volume0Serial", "VolumeSerial"],
}

# PECmd writes the older executions as PreviousRun0 .. PreviousRun6, giving up
# to seven timestamps in addition to LastRun.
PREVIOUS_RUN_COLUMNS = [f"PreviousRun{index}" for index in range(7)]

# Prefetch stores paths in volume-device form, e.g.
# \VOLUME{01d9a...}\USERS\ANALYST\EVIL.EXE - this matches that prefix so it
# can be rewritten to a normal drive letter.
VOLUME_PREFIX_RE = re.compile(r"\\VOLUME\{[^}]+\}", re.IGNORECASE)


def _resolve_columns(dataframe):
    """
    Map each internal field name to the real column in this CSV, or None.

    Done once per file so the per-row loop never repeats the lookup work.
    """
    available = {str(column).strip().lower(): column
                 for column in dataframe.columns}
    resolved = {}
    for field, aliases in COLUMN_ALIASES.items():
        resolved[field] = next(
            (available[alias.lower()] for alias in aliases
             if alias.lower() in available),
            None,
        )
    return resolved


def _cell(row, column):
    """
    Read one cell as a clean string.

    Returns "" for a missing column or an empty/placeholder value, so callers
    never deal with None or NaN.
    """
    if column is None:
        return ""
    value = row.get(column, "")
    if value is None:
        return ""
    text = str(value).strip()
    return "" if text.lower() in ("nan", "n/a", "null", "none") else text


def _split_list(text):
    """
    Split one of PECmd's comma-packed multi-value cells into a list.

    FilesLoaded and Directories both cram many values into a single cell;
    empty fragments are discarded.
    """
    return [part.strip() for part in (text or "").split(",") if part.strip()]


def _to_utc(text):
    """
    Convert a timestamp string to an ISO-8601 UTC string.

    A naive timestamp is assumed to be UTC because PECmd emits UTC. Returns ""
    when missing or unparseable, rather than dropping the row.
    """
    if not text:
        return ""
    try:
        parsed = date_parser.parse(text)
    except (ValueError, OverflowError, TypeError):
        return ""
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def _recover_full_path(executable_name, files_loaded):
    """
    Reconstruct the executable's full path from the FilesLoaded list.

    PECmd's ExecutableName column is only a file name. The real path is hidden
    inside FilesLoaded, which lists every file touched during execution -
    including the executable itself, written in volume-device form. We look for
    the loaded .EXE whose file name matches the executable, then rewrite the
    \\VOLUME{...} prefix to C: so the path looks like a normal Windows path.

    Returns "" when no match is found; the row is still kept, just without a
    path, because the execution evidence itself is still valuable.
    """
    stem = executable_name.upper().removesuffix(".EXE")
    matches = []

    for entry in files_loaded:
        if not entry.upper().endswith(".EXE"):
            continue
        leaf = entry.replace("/", "\\").split("\\")[-1].upper().removesuffix(".EXE")
        if leaf.startswith(stem):
            matches.append(entry)

    if not matches:
        return ""

    # The longest match is the most specific (deepest) path.
    best_match = max(matches, key=len)
    return VOLUME_PREFIX_RE.sub("C:", best_match)


def parse(csv_path):
    """
    Parse a PECmd CSV into TRACE rows.

    Builds the execution timeline by combining LastRun with whichever
    PreviousRun0..6 columns this CSV actually has, giving up to eight distinct
    execution timestamps per program.

    Raises ValueError when ExecutableName is missing, since without it the file
    is not a Prefetch export TRACE can use.
    """
    dataframe = pd.read_csv(csv_path, dtype=str, keep_default_na=False,
                            on_bad_lines="skip")
    columns = _resolve_columns(dataframe)

    if columns["executable_name"] is None:
        raise ValueError(
            "This does not look like a Prefetch CSV - no ExecutableName column "
            f"found. Columns seen: {list(dataframe.columns)[:12]}"
        )

    # Only the PreviousRunN columns this particular CSV contains.
    available = {str(column).strip().lower(): column
                 for column in dataframe.columns}
    previous_run_columns = [available[name.lower()]
                            for name in PREVIOUS_RUN_COLUMNS
                            if name.lower() in available]

    rows = []
    for _, record in dataframe.iterrows():
        executable_name = _cell(record, columns["executable_name"])
        if not executable_name:
            continue                      # nothing identifiable in this row

        files_loaded = _split_list(_cell(record, columns["files_loaded"]))
        full_path = _recover_full_path(executable_name, files_loaded)

        # Execution timeline: most recent run first, then each previous run.
        last_run = _to_utc(_cell(record, columns["last_run"]))
        run_history = [last_run] if last_run else []
        for column in previous_run_columns:
            previous = _to_utc(_cell(record, column))
            if previous and previous not in run_history:
                run_history.append(previous)

        # RunCount arrives as a string and is occasionally blank or malformed.
        try:
            run_count = int(float(_cell(record, columns["run_count"])))
        except (TypeError, ValueError):
            run_count = 0

        rows.append({
            "source":              "prefetch",
            "name":                full_path.split("\\")[-1] if full_path else executable_name,
            "full_path":           full_path,
            "sha1":                "",     # Prefetch never records file hashes
            "timestamp_utc":       last_run,
            "run_count":           run_count,
            "run_history_utc":     run_history,
            "files_loaded":        files_loaded,
            "directories":         _split_list(_cell(record, columns["directories"])),
            "prefetch_hash":       _cell(record, columns["prefetch_hash"]),
            "source_filename":     _cell(record, columns["source_filename"]),
            "source_created_utc":  _to_utc(_cell(record, columns["source_created"])),
            "source_modified_utc": _to_utc(_cell(record, columns["source_modified"])),
            "volume_name":         _cell(record, columns["volume_name"]),
            "volume_serial":       _cell(record, columns["volume_serial"]),
            "executed":            True,   # a .pf file existing IS proof it ran
        })

    print(f"[prefetch_parser] {len(rows)} entries parsed from {csv_path}")
    return rows
