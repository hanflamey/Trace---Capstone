import json
import urllib.request
from pathlib import Path

from backend import config

# Official MITRE ATT&CK STIX bundle.
_STIX_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
             "/master/enterprise-attack/enterprise-attack.json")

# Human-readable tactic names.
_TACTIC_DISPLAY = {
    "initial-access":       "Initial Access",
    "execution":            "Execution",
    "persistence":          "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion":      "Defense Evasion",
    "credential-access":    "Credential Access",
    "discovery":            "Discovery",
    "lateral-movement":     "Lateral Movement",
    "collection":           "Collection",
    "command-and-control":  "Command & Control",
    "exfiltration":         "Exfiltration",
    "impact":               "Impact",
    "resource-development": "Resource Development",
}

# ---------------------------------------------------------------------------
# THE CURATED MENU
# ---------------------------------------------------------------------------
# Techniques a program-execution artifact can plausibly evidence. The short
# descriptions are written for the prompt: they describe what the ANALYST would
# see in an Amcache/Prefetch/ShimCache row, not MITRE's full prose definition.
CURATED_TECHNIQUES: dict[str, str] = {
    # --- Execution ---
    "T1059":     "Command/script interpreter executed (cmd, powershell, wscript, cscript)",
    "T1059.001": "PowerShell used to execute commands or scripts",
    "T1059.003": "Windows command shell (cmd.exe) used to execute commands",
    "T1059.005": "Visual Basic script (.vbs) executed",
    "T1059.007": "JavaScript/JScript (.js, .jse) executed",
    "T1106":     "Native Windows API used directly to execute code",
    "T1204":     "User execution - victim ran a file delivered to them",
    "T1204.002": "User opened a malicious file (document, installer, archive)",
    "T1569.002": "Windows Service Control Manager used to execute a payload",
    "T1053.005": "Scheduled Task created or run to execute a payload",

    # --- Persistence ---
    "T1547":     "Autostart execution via registry Run keys or startup folder",
    "T1547.001": "Registry Run key or Startup folder used for persistence",
    "T1543.003": "Windows service created or modified for persistence",
    "T1546":     "Event-triggered execution used for persistence",
    "T1197":     "BITS jobs used to download or execute payloads persistently",

    # --- Defense Evasion ---
    "T1036":     "Masquerading - file name or location imitates a legitimate binary",
    "T1036.003": "Renamed legitimate system utility used to evade detection",
    "T1036.005": "Malicious file placed in a trusted location to appear legitimate",
    "T1218":     "Signed binary proxy execution (LOLBin) used to run payload",
    "T1218.005": "mshta.exe used to execute script content",
    "T1218.010": "regsvr32.exe used to execute a DLL or scriptlet",
    "T1218.011": "rundll32.exe used to execute a DLL export",
    "T1027":     "Obfuscated, packed or encoded file to hinder analysis",
    "T1070.004": "File deleted to remove evidence of execution",
    "T1112":     "Registry modified to weaken defences or hide activity",
    "T1140":     "Deobfuscation/decoding utility (certutil) used on payload",
    "T1562.001": "Security tooling disabled or tampered with",
    "T1055":     "Process injection used to run code in another process",

    # --- Discovery ---
    "T1082":     "System information discovery utility executed",
    "T1087":     "Account discovery utility executed",
    "T1018":     "Remote system discovery utility executed",
    "T1057":     "Process discovery utility executed",
    "T1016":     "Network configuration discovery utility executed",
    "T1083":     "File and directory discovery activity",

    # --- Credential Access ---
    "T1003":     "Credential dumping tool executed (e.g. mimikatz-class tool)",
    "T1003.001": "LSASS memory dumped to harvest credentials",

    # --- Lateral Movement / Remote tooling ---
    "T1021":     "Remote services used for lateral movement",
    "T1570":     "Tool transferred laterally onto this host",

    # --- Impact ---
    "T1486":     "Ransomware/encryption binary executed",
    "T1490":     "Recovery inhibited (shadow copies deleted, backups removed)",
}

_table: dict[str, tuple[str, str]] | None = None

# Counts IDs the model produced that are not real ATT&CK techniques.
_hallucinated: list[str] = []


# ---------------------------------------------------------------------------
# STIX loading
# ---------------------------------------------------------------------------

def _ensure_stix_file() -> Path:
    """Download the STIX bundle on first use if it is not already on disk."""
    path: Path = config.MITRE_STIX_FILE
    if path.exists():
        return path

    path.parent.mkdir(parents=True, exist_ok=True)
    print("[mitre] enterprise-attack.json not found - downloading from MITRE ...")
    try:
        urllib.request.urlretrieve(_STIX_URL, path)
        print(f"[mitre] downloaded {path.stat().st_size / 1_048_576:.1f} MB")
    except Exception as exc:
        raise RuntimeError(
            f"Could not download MITRE ATT&CK data: {exc}. Download it manually "
            f"to {path} from {_STIX_URL}"
        )
    return path


def _parse_stix(path: Path) -> dict[str, tuple[str, str]]:
    """
    Build {technique_id: (name, tactic)} from the STIX bundle.

    Revoked and deprecated techniques are included as fallbacks so that an ID
    from an older ATT&CK version still resolves to a real name instead of
    being mistaken for a hallucination. Active definitions take precedence.
    """
    bundle = json.loads(path.read_text(encoding="utf-8"))

    active: dict[str, tuple[str, str]] = {}
    legacy: dict[str, tuple[str, str]] = {}

    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue

        technique_id = next(
            (ref.get("external_id", "") for ref in obj.get("external_references", [])
             if ref.get("source_name") == "mitre-attack"),
            "",
        )
        if not technique_id:
            continue

        phases = [p for p in obj.get("kill_chain_phases", [])
                  if p.get("kill_chain_name") == "mitre-attack"]
        tactic = (_TACTIC_DISPLAY.get(phases[0]["phase_name"].lower(),
                                      phases[0]["phase_name"].replace("-", " ").title())
                  if phases else "")

        record = (obj.get("name", ""), tactic)
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            legacy[technique_id] = record
        else:
            active[technique_id] = record

    table = {**legacy, **active}
    print(f"[mitre] loaded {len(active)} active + {len(legacy)} legacy techniques")
    return table


def _get_table() -> dict[str, tuple[str, str]]:
    """Return the full technique table, loading it on first call."""
    global _table
    if _table is None:
        _table = _parse_stix(_ensure_stix_file())
    return _table


# ---------------------------------------------------------------------------
# LAYER 1: Grounding - the menu handed to the model
# ---------------------------------------------------------------------------

def prompt_menu() -> str:
    """
    Render the curated techniques as a closed menu for the LLM system prompt.

    Only techniques that exist in the loaded STIX bundle are offered, so the
    menu itself can never introduce an invalid ID.

    Format is deliberately terse - "T1036 Masquerading" rather than the ID plus
    the official name plus a description. The menu is repeated in every system
    prompt for every batch, and on a 7B model the space it consumes competes
    directly with attention on the actual evidence. The technique names alone
    are enough for the model to choose correctly.
    """
    table = _get_table()
    lines = []
    for technique_id in CURATED_TECHNIQUES:
        if technique_id in table:
            lines.append(f"{technique_id} {table[technique_id][0]}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# LAYER 2: Validation - nothing invalid reaches a report
# ---------------------------------------------------------------------------

def validate(technique_ids: list[str]) -> list[str]:
    """
    Keep only IDs that exist in the full ATT&CK table.

    A sub-technique the model invented (T1059.999) falls back to its real
    parent (T1059) rather than being discarded outright. Anything still
    unrecognised is dropped and recorded for the hallucination-rate metric.
    """
    table = _get_table()
    valid: list[str] = []

    for raw in technique_ids:
        candidate = (raw or "").strip().upper()
        if not candidate:
            continue

        if candidate in table:
            valid.append(candidate)
        elif "." in candidate and candidate.split(".")[0] in table:
            parent = candidate.split(".")[0]
            print(f"[mitre] {candidate} unknown - falling back to parent {parent}")
            valid.append(parent)
        else:
            _hallucinated.append(candidate)
            print(f"[mitre] REJECTED hallucinated technique id: {candidate}")

    return valid


def map_techniques(technique_ids: list[str]) -> list[dict]:
    """
    Resolve validated IDs to full records for the report.

    Returns [{"id", "name", "tactic", "url"}], de-duplicated, input order kept.
    """
    table = _get_table()
    records: list[dict] = []
    seen: set[str] = set()

    for technique_id in validate(technique_ids):
        if technique_id in seen:
            continue
        seen.add(technique_id)

        name, tactic = table[technique_id]
        # Sub-technique URLs use a slash: T1059.001 -> /T1059/001
        url_path = technique_id.replace(".", "/")
        records.append({
            "id":     technique_id,
            "name":   name,
            "tactic": tactic,
            "url":    f"https://attack.mitre.org/techniques/{url_path}/",
        })

    return records


def hallucination_report() -> dict:
    """Expose how often the model produced invalid IDs, for the PDF metadata."""
    return {
        "rejected_count": len(_hallucinated),
        "rejected_ids":   sorted(set(_hallucinated))[:20],
    }


def preload() -> None:
    """Load STIX at server startup so the first analysis is not delayed."""
    _get_table()
