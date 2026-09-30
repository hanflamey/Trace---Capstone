import pandas as pd
from dateutil import parser as date_parser
from datetime import timezone


# Every internal field mapped to the column names Eric Zimmerman's tools have
# used across versions. Resolution is case-insensitive and takes the first
# alias that exists, so one parser handles old and new CSV layouts.
COLUMN_ALIASES = {
    "name":               ["Name", "ApplicationName", "FileName", "ProgramName"],
    "full_path":          ["FullPath", "Path", "FilePath"],
    "sha1":               ["SHA1", "Sha1", "SHA-1"],
    "last_write":         ["FileKeyLastWriteTimestamp", "LastWriteTimestamp",
                           "KeyLastWriteTimestamp", "LastWrite"],
    "link_date":          ["LinkDate", "PELinkDate", "CompileTime"],
    "product_name":       ["ProductName", "Product"],
    # Publisher is the single strongest signing signal Amcache carries: a
    # non-Microsoft executable with no publisher is unsigned, which is a
    # primary indicator of a repacked or portable binary.
    "publisher":          ["Publisher", "CompanyName", "Company"],
    "is_os_component":    ["IsOsComponent", "IsOSComponent", "OsComponent"],
    "description":        ["Description", "FileDescription"],
    "original_file_name": ["OriginalFileName", "OriginalName"],
    "version":            ["Version", "BinFileVersion", "ProductVersion",
                           "FileVersionString"],
    "is_pe_file":         ["IsPeFile", "IsPEFile", "PeFile"],
}


def _resolve_columns(dataframe):
    """
    Map each internal field name to the real column in this CSV, or None.

    Returns a dict like {"sha1": "SHA1", "name": "Name", "description": None}.
    Called once per file so the per-row loop never repeats the lookup work.
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

    Returns "" when the column is absent from this CSV or the cell is empty,
    so callers never have to handle None or NaN.
    """
    if column is None:
        return ""
    value = row.get(column, "")
    if value is None:
        return ""
    text = str(value).strip()
    return "" if text.lower() in ("nan", "n/a", "null", "none") else text


def _to_bool(text):
    """
    Interpret the several ways EZ tools spell a boolean in a CSV cell.

    "True", "true", "1", "yes" all mean True; anything else means False.
    """
    return text.strip().lower() in ("true", "1", "yes", "y")


def _to_utc(text):
    """
    Convert a timestamp string to an ISO-8601 UTC string.

    Amcache timestamps can arrive with or without timezone information. A
    naive timestamp is assumed to already be UTC, because Eric Zimmerman's
    tools emit UTC. Returns "" when the value is missing or unparseable - a
    bad date must never discard the row, since the file itself is still
    evidence.
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


def parse(csv_path):
    """
    Parse an AmcacheParser CSV into TRACE rows.

    Reads with dtype=str so SHA-1 values and timestamps are never mangled into
    floats by pandas, skips malformed lines rather than aborting the whole
    investigation, and drops rows that have neither a name nor a path (those
    carry no evidence at all).

    Raises ValueError when the file has no recognisable Amcache columns, so the
    analyst gets a clear message instead of an empty result.
    """
    dataframe = pd.read_csv(csv_path, dtype=str, keep_default_na=False,
                            on_bad_lines="skip")
    columns = _resolve_columns(dataframe)

    if columns["full_path"] is None and columns["name"] is None:
        raise ValueError(
            "This does not look like an Amcache CSV - no path or name column "
            f"found. Columns seen: {list(dataframe.columns)[:12]}"
        )

    rows = []
    for _, record in dataframe.iterrows():
        full_path = _cell(record, columns["full_path"])
        name = _cell(record, columns["name"])

        # Derive the file name from the path when the CSV only gave a path.
        if not name and full_path:
            name = full_path.replace("/", "\\").rstrip("\\").split("\\")[-1]

        # A row with neither identifier is unusable - skip it.
        if not name and not full_path:
            continue

        rows.append({
            "source":             "amcache",
            "name":               name,
            "full_path":          full_path,
            "sha1":               _cell(record, columns["sha1"]).lower(),
            "timestamp_utc":      _to_utc(_cell(record, columns["last_write"])),
            "link_date_utc":      _to_utc(_cell(record, columns["link_date"])),
            "product_name":       _cell(record, columns["product_name"]),
            "publisher":          _cell(record, columns["publisher"]),
            # CRITICAL: whether the CSV even HAS a publisher column, which is
            # not the same question as whether this row has a publisher value.
            #
            # AmcacheParser's UnassociatedFileEntries export contains no
            # Publisher column at all. Without this flag every row from such a
            # file looks unsigned, and the AI then reports signed Microsoft
            # binaries as "fake unsigned copies" - which is exactly what
            # happened before this was added.
            "publisher_recorded": columns["publisher"] is not None,
            "is_os_component":    _to_bool(_cell(record, columns["is_os_component"])),
            "description":        _cell(record, columns["description"]),
            "original_file_name": _cell(record, columns["original_file_name"]),
            "version":            _cell(record, columns["version"]),
            "is_pe_file":         _to_bool(_cell(record, columns["is_pe_file"])),
        })

    print(f"[amcache_parser] {len(rows)} entries parsed from {csv_path}")
    return rows
