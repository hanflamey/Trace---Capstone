import pandas as pd
from dateutil import parser as date_parser
from datetime import timezone

# Only the three fields TRACE reasons about need alias resolution; all other
# columns are carried through untouched by parse().
COLUMN_ALIASES = {
    "path":      ["Path", "FullPath"],
    "timestamp": ["LastModifiedTimeUTC", "LastModifiedTime"],
    "executed":  ["Executed"],
}


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


def _to_utc(text):
    """
    Convert a timestamp string to an ISO-8601 UTC string.

    The source column is already named ...TimeUTC, so a naive value is taken
    as UTC. Returns "" when missing or unparseable rather than dropping the row.
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
    Parse an AppCompatCacheParser CSV into TRACE rows.

    Keeps every column in the source CSV: the fields TRACE reasons about are
    normalised into fixed names, and everything else is passed through with a
    lower-cased key so no evidence is silently discarded.

    Raises ValueError when there is no Path column, since that is the one field
    ShimCache cannot be useful without.
    """
    dataframe = pd.read_csv(csv_path, dtype=str, keep_default_na=False,
                            on_bad_lines="skip")
    columns = _resolve_columns(dataframe)

    if columns["path"] is None:
        raise ValueError(
            "This does not look like a ShimCache CSV - no Path column found. "
            f"Columns seen: {list(dataframe.columns)[:12]}"
        )

    # Columns already represented by a fixed field name, so they are not
    # duplicated when the remaining columns are passed through below.
    handled = {columns["path"], columns["timestamp"], columns["executed"]}

    rows = []
    for _, record in dataframe.iterrows():
        full_path = _cell(record, columns["path"])
        if not full_path:
            continue                      # no path means no evidence

        name = full_path.replace("/", "\\").rstrip("\\").split("\\")[-1]

        # Executed is tri-state: Yes / No / column not present at all. None is
        # meaningfully different from False - it means this CSV cannot tell us.
        executed_text = _cell(record, columns["executed"])
        if executed_text:
            executed = executed_text.lower() in ("true", "1", "yes", "y")
        else:
            executed = None

        row = {
            "source":        "shimcache",
            "name":          name,
            "full_path":     full_path,
            "sha1":          "",           # ShimCache never records file hashes
            "timestamp_utc": _to_utc(_cell(record, columns["timestamp"])),
            "executed":      executed,
        }

        # Pass through every remaining column so nothing is lost.
        for column in dataframe.columns:
            if column in handled:
                continue
            value = _cell(record, column)
            if value:
                row[str(column).strip().lower()] = value

        rows.append(row)

    print(f"[shimcache_parser] {len(rows)} entries parsed from {csv_path}")
    return rows
