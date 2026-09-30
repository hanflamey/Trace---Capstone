import json
import re

from backend.pipeline import mitre


# ---------------------------------------------------------------------------
# Shared scoring guidance
# ---------------------------------------------------------------------------
# Included in both passes so a category scores the same whichever pass
# assigns it. Without this, identical files score differently between runs.
SEVERITY_GUIDANCE = SEVERITY_GUIDANCE = """HOW TO JUDGE
Judge on what the file DOES and how it got there, not on whether you recognise
its name. Attackers deliberately use real, well-known tool names and place
files in locations that look ordinary.

PLACEMENT. Windows and legitimate vendors relocate their own components
constantly - each major Windows update, feature update, or security-platform
update can introduce a new install directory for an existing component. Judge
a path by what KIND of location it is, not by whether you personally
recognise that exact subfolder:
  1. OS-managed or vendor-managed namespace: anywhere under the Windows
     directory itself, under a vendor's folder in ProgramData, or inside a
     proper Program Files installation. A component here is normal even if
     the specific subfolder looks unfamiliar or was only introduced in a
     recent Windows version - an OS component moving to a new directory
     between Windows releases is expected, not evidence of tampering. A
     per-user vendor folder under the user's own app-data area (an
     application's own subfolder, not a bare temp or downloads path) counts
     the same way.
  2. Installer staging: a folder named with a GUID (the standard
     {8-4-4-4-12} hexadecimal format used by Windows Installer and most
     installer frameworks) holding setup components is ordinary installer
     behaviour wherever it sits - Temp, AppData\\Local\\Temp, or elsewhere.
     So is a file with a Windows-Installer-style temp name (a short
     alphanumeric filename with a .tmp extension).
  3. General-purpose, user-writable location: a loose, standalone executable
     in a temp folder, downloads folder, or user profile root that is NOT
     inside a GUID-named installer staging folder and has no matching
     installation around it. THIS is what should raise suspicion - especially
     when the file's own hash value reappears as its parent folder name,
     which is a classic malware self-staging pattern, not an installer one.

A well-known, legitimate tool placed in category 3 is MORE suspicious, not
less - it suggests someone dropped a portable copy on purpose. A file marked
`is_os_component` is genuine Windows machinery: never flag it, whatever its
path looks like. Do not assume a system component has only one valid
location - the same binary can legitimately exist at an old and a new path
across Windows versions at once.

SIGNING. A file with no recorded publisher is only "unsigned" when the source
data actually checked for one and found none (`publisher_recorded` true, no
publisher present). If publisher was never recorded at all for this artifact
type, that is unknown, not unsigned - do not treat it as suspicious by itself.
An unsigned executable outside a normal installation is a real signal; an
unsigned executable is not automatically evidence of anything on its own.

LINK DATE. A PE compile/link date that is zeroed or falls in the future is
WEAK evidence on its own, never proof of tampering. Modern Windows binaries
and many toolchains use deterministic/reproducible builds, where this field
holds a hash of the binary rather than a real timestamp - a nonsensical date
is common on completely legitimate, signed system files and proves nothing by
itself. Only let a link-date anomaly raise severity when it is corroborated by
at least one independent signal: genuine unsigned status, a general-purpose
user-writable location (category 3 above), a name that imitates another
binary, or an actual antivirus detection. Never use a link-date anomaly alone
to justify "tampered" or "replaced" language or a high severity score.

CAPABILITY. Once a file is already worth a second look by placement or
signing, weigh what it is capable of. As a general guide:
  10   malware, ransomware, credential dumping, known offensive tooling
   9   network/host reconnaissance and enumeration tools
   9   anti-forensics: log clearing, history/artifact wiping, shadow-copy
       deletion
   9   remote software deployment / mass-execution tooling
 8.5   remote access, remote monitoring, or remote management tooling
   8   file transfer, cloud sync, or cloud storage tools that move data off
       the machine
   8   screen capture, keylogging, or clipboard monitoring
   7   a scripting language or runtime interpreter running from somewhere
       other than its own normal install
 6-8   an executable with a random, meaningless, or deliberately generic name
       in a temp, downloads, or general user-writable folder, capability
       otherwise unclear

DO NOT FLAG:
 * `is_os_component` is true - never overridden by path or publisher.
 * Mainstream software correctly installed in its own product directory,
   even if the tool itself is a remote-access, sync, or admin tool. Correct
   installation is what decides this, not what the tool can do.
 * A component under the Windows directory, a vendor's ProgramData folder, or
   Program Files, even at a subfolder you don't specifically recognise -
   Windows and vendors relocate their own components across versions.
 * A file only because publisher was never recorded for this artifact type -
   that is unknown, not unsigned.
 * A file inside a GUID-named installer staging folder, or with a
   Windows-Installer-style temp filename.
 * A clean result from multiple independent antivirus engines combined with a
   real, matching product identity. That overrides an initial suspicion.
 * A link-date anomaly with no other corroborating signal.

Never describe a file as "fake", "tampered", "replaced", or "spoofed" without
a concrete reason you were actually given - an antivirus detection, a
genuine signing mismatch, or a name that imitates another binary. An
unfamiliar name, vendor, or subfolder is not evidence of tampering by itself.

When you are not genuinely confident a file is suspicious, do not include it.
A missed low-confidence entry is a smaller problem than a wave of false
positives burying the real findings."""

# ---------------------------------------------------------------------------
# PASS 1 - initial metadata-only assessment
# ---------------------------------------------------------------------------

PASS1_SYSTEM_TEMPLATE = """You are a senior Windows digital forensics analyst reviewing program-execution artifacts (Amcache, Prefetch, ShimCache).

Your task is to identify entries that are malicious or genuinely suspicious, based only on the metadata provided. You have no antivirus data at this stage - judge from file name, path, publisher, version and timing.

{severity_guidance}

When you assign a MITRE ATT&CK technique you MUST pick an ID from this list, or return an empty string. Never invent a technique ID:

{mitre_menu}

Respond with valid JSON only. No prose, no explanations outside the JSON, no markdown code fences."""


PASS1_USER_TEMPLATE = """Analyze these Windows artifact entries. Return a JSON array containing ONLY the entries you consider suspicious or malicious.

Each array item must be exactly:
{{
  "entry_id": <integer id copied from the entry>,
  "justification": "<what signal you saw, how an attacker would use it, and the next investigative step>",
  "mitre_technique": "<one ID from the approved list, or empty string>",
  "severity_score": <number between 0 and 10>
}}

If nothing here is suspicious, return exactly: []

Entries:
{entries}"""


def build_pass1_system_prompt():
    """
    Build the Pass 1 system prompt with the grounded MITRE menu inserted.

    The menu is generated from the real ATT&CK data at runtime, so the model
    can only choose techniques that actually exist.
    """
    return PASS1_SYSTEM_TEMPLATE.format(
        severity_guidance=SEVERITY_GUIDANCE,
        mitre_menu=mitre.prompt_menu(),
    )


def format_pass1_entry(entry_id, row):
    """
    Render one parsed row as compact JSON for the Pass 1 prompt.

    Only fields that inform the judgement are included. Sending every field
    would bury the signal in blanks, since each artifact type leaves most of
    the others' fields empty.
    """
    entry = {
        "id":        entry_id,
        "name":      row.get("name", ""),
        "full_path": row.get("full_path", ""),
        "seen_in":   row.get("seen_in_sources", [row.get("source", "")]),
        "timestamp": row.get("timestamp_utc", ""),
    }

    # --- signing and identity metadata -----------------------------------
    # CRITICAL DISTINCTION. Only Amcache records publisher, product and
    # version. If Amcache never saw this file, those fields are simply
    # UNKNOWN - which is completely different from Amcache seeing it and
    # finding no publisher (genuinely unsigned).
    #
    # Conflating the two would make every Prefetch-only entry look unsigned,
    # turning ordinary Windows binaries like svchost.exe into false positives.
    # The wording below tells the model exactly which situation it is in.
    # "Unsigned" may only be claimed when the source CSV actually HAD a
    # publisher column and this row's value was empty. Some AmcacheParser
    # exports (UnassociatedFileEntries) contain no Publisher column at all -
    # treating that as unsigned makes every Microsoft binary look tampered
    # with, which produced a wave of false positives before this check.
    publisher = row.get("publisher", "")
    if publisher:
        entry["publisher"] = publisher
    elif row.get("publisher_recorded"):
        entry["publisher"] = "(none - file is UNSIGNED)"
    else:
        # Kept short: this string repeats on every entry in every batch, and
        # a long sentence here crowds out the actual evidence.
        entry["publisher"] = "(unknown)"

    # Product name is only shown when there is one. An absent field reads as
    # "unknown", which is correct for artifacts that never record it - showing
    # an empty value would invite the model to treat missing data as a signal.
    product = row.get("product_name", "")
    if product:
        entry["product_name"] = product

    if row.get("description"):
        entry["description"] = row["description"]
    if row.get("version"):
        entry["version"] = row["version"]

    # A zeroed PE compile date is flagged in words, because "1970-01-01" alone
    # is easy for a small model to read as just an old date rather than as a
    # deliberately stripped timestamp.
    compile_date = row.get("link_date_utc", "")
    if compile_date:
        if compile_date.startswith("1970-01-01"):
            entry["pe_compile_date"] = "ZEROED/STRIPPED"
        else:
            entry["pe_compile_date"] = compile_date[:10]

    if row.get("is_os_component"):
        entry["is_os_component"] = True

    # A mismatch between OriginalFileName and the name on disk is a classic
    # masquerading signal, so it is called out explicitly when they differ.
    original = row.get("original_file_name", "")
    if original and original.lower() != row.get("name", "").lower():
        entry["original_file_name"] = f"{original} (DIFFERS from file name)"

    # --- execution evidence ----------------------------------------------
    if row.get("run_count"):
        entry["run_count"] = row["run_count"]
    if row.get("executed"):
        entry["execution_confirmed"] = True

    return json.dumps(entry, ensure_ascii=False)


# ---------------------------------------------------------------------------
# PASS 2 - reconciliation against threat intel and cross-artifact evidence
# ---------------------------------------------------------------------------

PASS2_SYSTEM_TEMPLATE = """You are a senior Windows digital forensics analyst producing a FINAL verdict on a file.

You are given: the file's metadata, an initial assessment you made from metadata alone, real antivirus results for its hash, and cross-artifact execution evidence.

How to weigh the evidence:
  - Antivirus detections from many independent engines are strong, factual evidence. Five or more engines agreeing means the file IS malicious - say so plainly and score at least 9.0.
  - A file scanned CLEAN by many engines (for example 0 of 74) is strong evidence in the OTHER direction. If it also has a legitimate product identity or is a Windows component, your first impression was wrong - score it 3.0 or below and say the antivirus result overrode your initial read. Do not keep a high score by inventing tampering that no evidence supports.
  - A hash NOT FOUND in any source is different from a hash scanned clean. Not-found means untested - freshly compiled or targeted malware looks exactly like this, so judge those files on metadata and behaviour.
  - One or two engine detections are weak and are often false positives - weigh them, do not treat them as proof.
  - Proven execution (Prefetch, or ShimCache Executed=Yes) makes a suspicious file more serious than mere presence on disk. Repeated execution is more serious still. But execution alone is not suspicious: every normal program on the machine also executed.

{severity_guidance}

For the MITRE ATT&CK technique: you previously proposed one. Keep it if the new evidence supports it. Change it only if the evidence points somewhere else. Either way the ID MUST come from this list, or be an empty string:

{mitre_menu}

Respond with valid JSON only. No prose outside the JSON, no markdown code fences."""


PASS2_USER_TEMPLATE = """Produce your final verdict on each file below. Return a JSON array with one item per file.

Each array item must be exactly:
{{
  "entry_id": <integer id copied from the file>,
  "final_score": <number between 0 and 10>,
  "mitre_technique": "<one ID from the approved list, or empty string>",
  "justification": "<your final reasoning, referring to the actual evidence you were given, and the recommended next step for the analyst>"
}}

Return one item for EVERY file listed, even if your verdict is that it is not a threat (score it low in that case).

Files:
{entries}"""


def build_pass2_system_prompt():
    """
    Build the Pass 2 system prompt with the same grounded MITRE menu.

    Using the identical menu in both passes means a technique confirmed in
    Pass 2 is always one the model was legitimately offered.
    """
    return PASS2_SYSTEM_TEMPLATE.format(
        severity_guidance=SEVERITY_GUIDANCE,
        mitre_menu=mitre.prompt_menu(),
    )


def format_pass2_entry(entry_id, row, initial, intel_summary, correlation):
    """
    Render one entry for the Pass 2 prompt, with all evidence attached.

    Combines four things the model needs to reconcile:
      - the file's identity (name, path, source artifact)
      - its Pass 1 verdict, so the model can confirm or revise its own reasoning
      - a curated antivirus summary from threat_intel.summarise_for_ai()
      - cross-artifact execution statements from correlation.evidence_for()

    Sections with nothing to report are omitted entirely rather than sent
    empty, to keep the prompt short for a small local model.
    """
    entry = {
        "id":        entry_id,
        "name":      row.get("name", ""),
        "full_path": row.get("full_path", ""),
        "source":    row.get("source", ""),
    }

    if row.get("product_name"):
        entry["product"] = row["product_name"]
    if row.get("version"):
        entry["version"] = row["version"]

    # What Pass 1 concluded from metadata alone.
    if initial:
        entry["your_initial_assessment"] = {
            "score":            initial.get("score", 0.0),
            "mitre_technique":  initial.get("mitre", "") or "none",
            "reasoning":        initial.get("justification", ""),
        }
    else:
        # Pass 1 did not flag it - it reached Pass 2 purely because threat
        # intel found something, which the model should know.
        entry["your_initial_assessment"] = (
            "You did not flag this file on metadata alone. "
            "It is being reviewed because antivirus data exists for its hash."
        )

    if intel_summary:
        entry["antivirus_results"] = intel_summary
    else:
        entry["antivirus_results"] = "No hash available for this file (only Amcache records hashes)."

    if correlation and correlation.get("statements"):
        entry["execution_evidence"] = correlation["statements"]

    return json.dumps(entry, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------

def extract_json_array(text):
    """
    Pull a JSON array out of a local model's response.

    Small models reliably do three things wrong, all handled here:
      - emitting a <think>...</think> reasoning block before the answer
      - wrapping the JSON in ```json code fences
      - surrounding the array with a sentence of explanation

    Returns a list, or None when nothing parseable was found.
    """
    if not text:
        return None

    # Strip reasoning blocks (Qwen "thinking" mode and similar).
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)

    # Prefer the contents of a fenced code block when one is present.
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    if fence:
        text = fence.group(1)

    text = text.strip()

    # Best case: the whole response is the JSON array.
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, list) else None
    except json.JSONDecodeError:
        pass

    # Fallback: slice from the first '[' to the last ']' and retry.
    start, end = text.find("["), text.rfind("]")
    if start >= 0 and end > start:
        try:
            parsed = json.loads(text[start:end + 1])
            return parsed if isinstance(parsed, list) else None
        except json.JSONDecodeError:
            pass

    return None


def clamp_score(value):
    """
    Coerce a model-supplied score into a valid 0-10 float.

    Models occasionally return a string, a null, or a number outside the range;
    all of those become a usable value instead of crashing the pipeline.
    """
    try:
        score = float(value)
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, min(10.0, score))
