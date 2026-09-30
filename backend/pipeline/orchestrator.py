import csv as csv_writer_module
from hashlib import sha1
import time
import uuid
from datetime import datetime, timezone

from backend import config
from backend.pipeline import (amcache_parser, correlation, local_llm, mitre,
                              prefetch_parser, report, scoring,
                              shimcache_parser, threat_intel)

# Which parser handles which uploaded artifact.
PARSERS = {
    "amcache":   amcache_parser,
    "prefetch":  prefetch_parser,
    "shimcache": shimcache_parser,
}


def run_pipeline(uploads, chain_of_custody=None):
    """
    Run the full analysis pipeline and return the API response.

    `uploads`           {"amcache": path, "prefetch": path, "shimcache": path}
                        Any subset. All values must be .csv files.
    `chain_of_custody`  optional case metadata from the frontend form

    Returns a dict of counts and findings, with the generated PDF and CSV paths
    under private "_" keys that main.py strips before responding.
    """
    started_at = time.time()
    report_id = uuid.uuid4().hex[:12]

    # =====================================================================
    # Collect the uploaded CSVs. TRACE takes CSV exports only - produce them
    # first with the matching Eric Zimmerman tool (AmcacheParser, PECmd,
    # AppCompatCacheParser) and upload the result.
    # =====================================================================
    csv_paths = {artifact: path for artifact, path in uploads.items() if path}
    # Whatever entry in the uploads dictionary that doesn't have a path it is remove 

    if not csv_paths:
        raise ValueError("No artifacts were uploaded.")

    for artifact, path in csv_paths.items():
        if not path.lower().endswith(".csv"):
            raise ValueError(
                f"The {artifact} upload is not a .csv file. TRACE analyses CSV "
                f"exports only - parse the raw artifact with the matching Eric "
                f"Zimmerman tool first, then upload the CSV it produces."
            )

    # =====================================================================
    # STAGE 1: Parse each CSV with its own parser (timestamps become UTC here)
    # =====================================================================
    rows = []
    entries_per_artifact = {}
    #Sends to parser files by reading
    for artifact, csv_path in csv_paths.items():
        parsed_rows = PARSERS[artifact].parse(csv_path)
        entries_per_artifact[artifact] = len(parsed_rows)
        rows.extend(parsed_rows)

    if not rows:
        raise ValueError("No usable entries were found in the uploaded artifacts.")

    total_entries = len(rows)
    print(f"[orchestrator] {total_entries} entries parsed in total")
   # breakpoint()

    # =====================================================================
    # STAGE 2: Correlate, then collapse to one row per unique executable
    # ---------------------------------------------------------------------
    # The index is built over the raw rows so it sees every artifact's view of
    # each executable. The collapse then merges those views into a single
    # enriched row, which matters for two reasons:
    #
    #   - Prefetch and ShimCache record no publisher, product or version. When
    #     Amcache saw the same file, that metadata is copied across, so the AI
    #     never has to judge a bare filename.
    #   - Each executable is assessed ONCE. Judging the same file once per
    #     artifact gave the model three independent chances to be wrong about
    #     it, and the worst verdict won.
    # =====================================================================
    correlation_index = correlation.build_index(rows)
    rows = correlation.collapse_to_executables(rows, correlation_index)
  #  breakpoint()
    # =====================================================================
    # STAGE 3: Threat intelligence on every hash, all sources at once
    # =====================================================================
    intel = threat_intel.lookup_all(rows)
  #  breakpoint() 
    # =====================================================================
    # STAGE 4: AI pass 1 - triage from metadata alone
    # =====================================================================
    pass1_results = local_llm.run_pass1(rows)
 #   breakpoint()
    # =====================================================================
    # STAGE 5: Choose who needs a final verdict, then run AI pass 2
    # ---------------------------------------------------------------------
    # An entry goes to pass 2 if EITHER:
    #   - pass 1 flagged it as suspicious, OR
    #   - threat intel found any signal for its hash
    #
    # The second condition is what guarantees a hash with real antivirus
    # detections is always reviewed, even when pass 1 ignored it because the
    # file name and path looked unremarkable.
    # =====================================================================
    candidates = []

    for index, row in enumerate(rows):
        intel_fields = threat_intel.fields_for(row.get("sha1", ""), intel)
        flagged_by_ai = index in pass1_results
        flagged_by_intel = threat_intel.has_signal(intel_fields)
      #  if "svch0st" in row.get("name", "").lower():
       #     breakpoint()

        if not flagged_by_ai and not flagged_by_intel:
            continue                       # nothing suspicious about this entry

        candidates.append({
            "index":         index,
            "row":           row,
            "initial":       pass1_results.get(index),
            "intel_fields":  intel_fields,
            "intel_summary": threat_intel.summarise_for_ai(intel_fields),
            "correlation":   correlation.evidence_for(row, correlation_index),
        })

    intel_only = sum(1 for candidate in candidates if candidate["initial"] is None)
    print(f"[orchestrator] {len(candidates)} entries go to pass 2 "
          f"({intel_only} of them because threat intel found a signal "
          f"that pass 1 missed)")

    pass2_results = local_llm.run_pass2(candidates)
 #   breakpoint()

    # =====================================================================
    # STAGE 6: Assemble findings, apply the scoring floor
    # =====================================================================
    findings = []

    for candidate in candidates:
        verdict = pass2_results.get(candidate["index"])

        # If pass 2 did not return a verdict for this entry (a malformed
        # response, for instance), fall back to the pass 1 result so the entry
        # is never silently lost from the report.
        if verdict is None:
            verdict = candidate["initial"] or {
                "score": 0.0, "justification": "", "mitre": "",
            }

        row = candidate["row"]
        intel_fields = candidate["intel_fields"]
        correlation_evidence = candidate["correlation"]
    #    if "svch0st" in row.get("name", "").lower():
     #       breakpoint()

        risk_score, severity, score_explanation = scoring.finalise(
            verdict.get("score", 0.0), intel_fields
        )

        # Skip entries the AI concluded are not a threat AND that threat intel
        # never confirmed - they were only reviewed out of caution.
        if severity == "INFO" and not threat_intel.is_confirmed_malware(
                intel_fields, config.TI_CONFIRM_THRESHOLD):
            continue

        findings.append({
            # --- identity ------------------------------------------------
            "source":        row.get("source", ""),
            "name":          row.get("name", "") or "-",
            "full_path":     row.get("full_path", "") or "-",
            "sha1":          row.get("sha1", ""),
            "timestamp_utc": row.get("timestamp_utc", ""),
            "product_name":  row.get("product_name", ""),
            "version":       row.get("version", ""),

            # --- AI verdict ----------------------------------------------
            "initial_score":     (candidate["initial"] or {}).get("score", 0.0),
            "risk_score":        risk_score,
            "severity":          severity,
            "justification":     verdict.get("justification", ""),
            "score_explanation": score_explanation,

            # --- execution evidence (Stage 2) -----------------------------
            "seen_in_sources":     row.get("seen_in_sources",
                                           correlation_evidence["sources"]),
            "execution_confirmed": correlation_evidence["executed"],
            "run_count":           correlation_evidence["run_count"],

            # --- MITRE technique (validated in both passes) ---------------
            "mitre": mitre.map_techniques(
                [verdict["mitre"]] if verdict.get("mitre") else []
            ),

            # --- threat intel fields (vt_*, md_*, otx_*) ------------------
            **intel_fields,
        })

    # No de-duplication needed here: Stage 2 already collapsed the artifact
    # rows to one per executable, so each finding is unique by construction.
    findings.sort(key=lambda finding: finding["risk_score"], reverse=True)
  #  breakpoint()

    # =====================================================================
    # STAGE 7: Write the deliverables
    # =====================================================================
    elapsed_seconds = round(time.time() - started_at, 2)

    metadata = {
        "report_id":          report_id,
        "artifacts":          entries_per_artifact,
        "total_entries":      total_entries,
        "pass1_flagged":      len(pass1_results),
        "pass2_reviewed":     len(candidates),
        "intel_only_reviews": intel_only,
        "flagged_count":      len(findings),
        "hashes_checked":     intel["hashes_checked"],
        "processing_seconds": elapsed_seconds,
        "generated_utc":      datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "correlation":        correlation.summary(correlation_index),
        "mitre_validation":   mitre.hallucination_report(),
    }
    if chain_of_custody:
        metadata.update(chain_of_custody)

    csv_path = str(config.OUTPUT_DIR / f"TRACE_findings_{report_id}.csv")
    _write_findings_csv(findings, csv_path)

    pdf_path = str(config.OUTPUT_DIR / f"TRACE_report_{report_id}.pdf")
    try:
        report.generate_report(findings, metadata, pdf_path)
    except Exception as error:
        # A PDF failure must not lose the analysis - JSON and CSV still stand.
        print(f"[orchestrator] WARNING: PDF generation failed: {error}")
        from pathlib import Path
        Path(pdf_path).write_text(f"Report generation error: {error}")

    print(f"[orchestrator] complete in {elapsed_seconds}s -> {len(findings)} findings")

    return {
        "report_id":           report_id,
        "artifacts":           entries_per_artifact,
        "total_entries":       total_entries,
        "pass1_flagged":       len(pass1_results),
        "pass2_reviewed":      len(candidates),
        "intel_only_reviews":  intel_only,
        "flagged_count":       len(findings),
        "critical_high_count": sum(1 for finding in findings
                                   if finding["severity"] in ("CRITICAL", "HIGH")),
        "clean_count":         max(0, total_entries - len(findings)),
        "hashes_checked":      intel["hashes_checked"],
        "processing_seconds":  elapsed_seconds,
        "correlation":         metadata["correlation"],
        "findings":            findings,
        "_pdf_path":           pdf_path,
        "_csv_path":           csv_path,
    }


# Columns written to the analyst-facing findings CSV, in order.
CSV_COLUMNS = [
    "name", "full_path", "sha1", "source", "timestamp_utc",
    "risk_score", "severity", "initial_score", "justification",
    "score_explanation",
    "execution_confirmed", "run_count", "seen_in_sources",
    "vt_verdict_label", "vt_detections", "vt_total_engines", "vt_malware_family",
    "md_verdict_label", "md_detections", "md_total_engines",
    "otx_pulse_count",
    "mitre",
]


def _write_findings_csv(findings, path):
    """
    Write one row per flagged executable to the findings CSV.

    List-valued fields are flattened to semicolon-separated strings so the file
    opens cleanly in Excel.
    """
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv_writer_module.writer(handle)
        writer.writerow(CSV_COLUMNS)

        for finding in findings:
            row = []
            for column in CSV_COLUMNS:
                if column == "mitre":
                    row.append("; ".join(technique["id"]
                                         for technique in finding.get("mitre", [])))
                elif column == "seen_in_sources":
                    row.append("; ".join(finding.get("seen_in_sources", [])))
                else:
                    row.append(finding.get(column, ""))
            writer.writerow(row)
