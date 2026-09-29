# Trace---Capstone
# TRACE

**Threat Reconnaissance & Artifact Correlation Engine**

TRACE triages Windows program-execution artifacts. An analyst uploads what they
pulled off a victim machine — Amcache, Prefetch and ShimCache — and TRACE parses
them, correlates them against each other, checks hashes against threat
intelligence, has a **local** LLM assess anything threat intel could not settle,
and produces a forensic PDF report plus a findings CSV.

All AI analysis runs on the analyst's own machine. No artifact data leaves the host.

---

## The pipeline

Each stage is one module. `backend/pipeline/orchestrator.py` is the only file
that knows the order, so reading it top to bottom explains the whole tool.

| Stage | Module | What it does |
|------:|--------|--------------|
| 1 | `amcache_parser.py`<br>`prefetch_parser.py`<br>`shimcache_parser.py` | One parser per artifact; each normalises its own timestamps to UTC |
| 2 | `correlation.py` | Index executables across all three artifacts (presence vs. proven execution) |
| 3 | `threat_intel.py` | Look up **every** hash in VirusTotal + MetaDefender + OTX |
| 4 | `local_llm.run_pass1` | AI triage from metadata alone |
| 5 | `local_llm.run_pass2` | AI final verdict, given antivirus + execution evidence |
| 6 | `scoring.py` | Confirmed-malware floor and severity band |
| 7 | `orchestrator.py` | Merge duplicate executables |
| 8 | `report.py` | PDF report + findings CSV |

### Three design decisions worth knowing

**Threat intel covers every hash, and runs before the AI's final verdict.** It
would be cheaper to look up only the files the AI already found suspicious —
but a local 9B model judges from filenames and paths, and a well-disguised
binary can easily look unremarkable. Antivirus telemetry is factual evidence
and must never be gated behind a language model's first impression. Only
Amcache carries hashes, and results are cached, so this is affordable.

**The AI runs twice, not once.** Pass 1 triages on metadata alone. Pass 2 then
re-reviews anything that either pass 1 flagged *or* that threat intelligence
reported detections for, this time with the antivirus results and
cross-artifact execution evidence supplied. The model produces the final score
having actually seen the evidence, instead of a formula blending numbers
afterwards.

**The model cannot invent ATT&CK techniques.** It picks from a closed menu of
execution-observable techniques supplied in the prompt, and every returned ID
is validated against the official ATT&CK catalogue before it can reach a
report. Rejections are counted and printed in the PDF.

---

## Setup

### 1. Python

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Local LLM (required)

Install [LM Studio](https://lmstudio.ai), download an instruct model (Qwen 7B/9B
class works well), open **Local Server**, and click **Start Server**.

### 3. Eric Zimmerman's tools (required only for raw artifacts)

Needed to upload raw hives rather than pre-parsed CSVs. **Windows only** — these
are compiled `.exe` tools requiring the
[.NET Desktop Runtime](https://dotnet.microsoft.com/download).

```powershell
# https://github.com/EricZimmerman/Get-ZimmermanTools
.\Get-ZimmermanTools.ps1 -outDir "C:\Forensic Program Files\Zimmerman"
```

TRACE invokes three of them:

| Artifact | Tool | Command TRACE runs |
|----------|------|--------------------|
| Amcache | `AmcacheParser.exe` | `-f <Amcache.hve> -i on --csv <dir> --csvf <name>.csv` |
| Prefetch | `PECmd.exe` | `-d <unzipped folder> -q --csv <dir> --csvf <name>.csv` |
| ShimCache | `AppCompatCacheParser.exe` | `-f <SYSTEM> --csv <dir> --csvf <name>.csv` |

### 4. Configure

```powershell
copy .env.example .env
```

Set `LOCAL_LLM_URL` and `LOCAL_LLM_MODEL`. Everything else is optional — add
threat-intel API keys only for the sources you want.

### 5. Run

```powershell
python -m uvicorn backend.main:app --reload --port 8000
```

Open <http://localhost:8000>.

---

## Collecting artifacts from the victim machine

| Artifact | Location | Upload as |
|----------|----------|-----------|
| Amcache | `C:\Windows\AppCompat\Programs\Amcache.hve` | the `.hve` file |
| ShimCache | `C:\Windows\System32\config\SYSTEM` | the SYSTEM hive |
| Prefetch | `C:\Windows\Prefetch\` | a **`.zip`** of the folder |

Prefetch is a folder of hundreds of `.pf` files and a browser cannot upload a
folder, so it must be zipped first.

Already-parsed CSVs from any of the three tools are also accepted and skip
Stage -1 entirely.

---

## Why three artifacts

None of them answers the whole question alone:

| Artifact | Proves | Also gives |
|----------|--------|------------|
| Amcache | a file was **present** | SHA-1 hash (the only source of hashes), publisher, version |
| Prefetch | a file **ran** | run count, up to 8 execution timestamps, loaded files |
| ShimCache | Windows evaluated it | an explicit `Executed` flag |

A file in Amcache alone existed on disk. The same file in Amcache *and* Prefetch
with a run count of 14 ran repeatedly. Stage 2 captures that difference and
Stage 5 hands it to the AI as evidence, which is why uploading all three is
worth it. Amcache is the most valuable single artifact because it is the only
one carrying hashes — without it, threat intelligence has nothing to look up.

---

## Output

- `data/outputs/TRACE_report_<id>.pdf` — executive summary, findings, execution
  evidence, IOCs, chain of custody (including the exact extraction commands TRACE
  ran), and a methodology statement
- `data/outputs/TRACE_findings_<id>.csv` — one row per flagged executable

---

## Project layout

```text
backend/
  config.py                  all tunable values, read from .env
  main.py                    FastAPI endpoints
  pipeline/
    extraction.py            Stage -1  EZ tool wrappers
    amcache_parser.py        Stage  1  Amcache CSV -> rows (hashes live here)
    prefetch_parser.py       Stage  1  Prefetch CSV -> rows (execution proof)
    shimcache_parser.py      Stage  1  ShimCache CSV -> rows
    correlation.py           Stage  2  cross-artifact evidence
    threat_intel.py          Stage  3  VT + MetaDefender + OTX coordination
    virustotal.py                      VT client (cache + rate limit)
    metadefender.py                    MetaDefender client
    otx.py                             OTX client
    ai_engine.py             Stages 4,5 prompts and response parsing
    local_llm.py             Stages 4,5 LM Studio client (both passes)
    mitre.py                           ATT&CK menu + validation
    scoring.py               Stage  6  confirmed-malware floor + severity
    orchestrator.py                    the map of the whole pipeline
    report.py                Stage  8  PDF builder
frontend/index.html          dashboard
data/                        uploads, work, outputs, caches, MITRE STIX
```

For authorized forensic and academic use only.
