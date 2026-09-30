from backend import config
from backend.pipeline import threat_intel

# A file confirmed malicious by real antivirus engines never scores below this.
CONFIRMED_MALWARE_FLOOR = 8.0


def severity_for(score):
    """
    Map a 0-10 risk score onto its severity band.

    Thresholds come from config so they can be tuned in .env without a code
    change: CRITICAL >= 7, HIGH >= 5, MEDIUM >= 3, otherwise INFO.
    """
    if score >= config.SEV_CRITICAL:
        return "CRITICAL"
    if score >= config.SEV_HIGH:
        return "HIGH"
    if score >= config.SEV_MEDIUM:
        return "MEDIUM"
    return "INFO"


def finalise(ai_score, intel_fields):
    """
    Apply the confirmed-malware floor and return (score, severity, explanation).

    `ai_score`      the final score from the AI reconciliation pass
    `intel_fields`  that file's flattened threat-intel fields

    The explanation string is stored on the finding and printed in the report,
    so an analyst can always see whether a score came from the model or was
    raised by the safety rail.
    """
    score = max(0.0, min(10.0, float(ai_score)))
    confirmed = threat_intel.is_confirmed_malware(
        intel_fields, config.TI_CONFIRM_THRESHOLD
    )

    if confirmed and score < CONFIRMED_MALWARE_FLOOR:
        explanation = (
            f"AI scored {score:.1f}, raised to {CONFIRMED_MALWARE_FLOOR:.1f} "
            f"because threat intelligence confirmed this hash as malicious "
            f"({config.TI_CONFIRM_THRESHOLD}+ antivirus engines)."
        )
        score = CONFIRMED_MALWARE_FLOOR
    elif confirmed:
        explanation = (
            f"AI score of {score:.1f} accepted; threat intelligence "
            f"independently confirms this hash as malicious."
        )
    else:
        explanation = f"AI assessed this file at {score:.1f} out of 10."

    score = round(score, 1)
    return score, severity_for(score), explanation
