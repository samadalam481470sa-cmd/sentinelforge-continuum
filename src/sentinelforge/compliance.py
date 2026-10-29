"""Evidence-oriented compliance control mapping, not certification."""
CONTROLS = {
    "AC-2": {"family": "Access Control", "evidence": ["identity lifecycle logs", "account reviews"]},
    "AU-6": {"family": "Audit and Accountability", "evidence": ["alert triage records", "audit review reports"]},
    "IR-4": {"family": "Incident Response", "evidence": ["case timeline", "incident response records"]},
    "SI-4": {"family": "System and Information Integrity", "evidence": ["monitoring coverage", "detection findings"]},
}


def assess(evidence: dict[str, list[str]]) -> dict:
    return {"controls": [
        {"control": control, "family": details["family"], "required_evidence": details["evidence"],
         "submitted": evidence.get(control, []),
         "status": "evidence-submitted" if evidence.get(control) else "missing-evidence"}
        for control, details in CONTROLS.items()
    ], "disclaimer": "Evidence presence does not establish control effectiveness or compliance."}
