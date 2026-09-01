cat > evidence_validator.py << 'PYEOF'
import json
import re
import sys
from pathlib import Path

IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
URL_PATTERN = re.compile(r'https?://[^\s\'"]+')
SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')

CLASSIFICATION_MAP = {
    "automated_bot": "automated",
    "interactive_attacker": "interactive",
}


def extract_referenced_values(assessment):
    text_blob = json.dumps(assessment)
    return {
        "ips": set(IP_PATTERN.findall(text_blob)),
        "urls": set(URL_PATTERN.findall(text_blob)),
        "hashes": set(SHA256_PATTERN.findall(text_blob)),
    }


def validate_assessment(assessment, session, session_iocs):
    result = {
        "session_id": session["session_id"],
        "supported_claims": [],
        "unsupported_claims": [],
        "classification_check": None,
    }

    known_ips = {i["value"] for i in session_iocs if i["type"] == "ip"}
    known_urls = {i["value"] for i in session_iocs if i["type"] == "url"}
    known_hashes = {i["value"] for i in session_iocs if i["type"] == "sha256"}

    referenced = extract_referenced_values(assessment)

    for ip in referenced["ips"]:
        if ip in known_ips:
            result["supported_claims"].append(f"IP {ip} confirmed in session IOCs")
        else:
            result["unsupported_claims"].append(f"IP {ip} mentioned but NOT found in extracted IOCs")

    for url in referenced["urls"]:
        if url in known_urls:
            result["supported_claims"].append(f"URL {url} confirmed in session IOCs")
        else:
            result["unsupported_claims"].append(f"URL {url} mentioned but NOT found in extracted IOCs")

    for h in referenced["hashes"]:
        if h in known_hashes:
            result["supported_claims"].append(f"Hash {h} confirmed in session IOCs")
        else:
            result["unsupported_claims"].append(f"Hash {h} mentioned but NOT found in extracted IOCs")

    ai_classification = assessment.get("classification")
    actual_classification = session.get("classification")
    expected = CLASSIFICATION_MAP.get(ai_classification)

    if expected and actual_classification:
        if expected == actual_classification:
            result["classification_check"] = f"MATCH: AI said '{ai_classification}', evidence-based classifier said '{actual_classification}'"
        else:
            result["classification_check"] = f"MISMATCH: AI said '{ai_classification}', evidence-based classifier said '{actual_classification}'"
    else:
        result["classification_check"] = "INCONCLUSIVE: could not compare classifications"

    result["verdict"] = "VALIDATED" if not result["unsupported_claims"] else "FLAGGED_FOR_REVIEW"
    return result


def main():
    if len(sys.argv) < 4:
        print("Usage: python3 evidence_validator.py <ai_assessments.jsonl> <sessions.jsonl> <iocs.jsonl> [output_file]")
        sys.exit(1)

    assessments_path, sessions_path, iocs_path = sys.argv[1], sys.argv[2], sys.argv[3]
    output_path = Path(sys.argv[4]) if len(sys.argv) > 4 else Path("evidence_validation.jsonl")

    with open(assessments_path) as f:
        assessments = [json.loads(line) for line in f if line.strip()]
    with open(sessions_path) as f:
        sessions = {s["session_id"]: s for s in (json.loads(line) for line in f if line.strip())}
    with open(iocs_path) as f:
        iocs = [json.loads(line) for line in f if line.strip()]

    results = []
    for assessment in assessments:
        sid = assessment.get("session_id")
        session = sessions.get(sid, {})
        session_iocs = [i for i in iocs if i.get("session_id") == sid]
        result = validate_assessment(assessment, session, session_iocs)
        results.append(result)

    with open(output_path, "w") as out:
        for r in results:
            out.write(json.dumps(r) + "\n")

    validated = sum(1 for r in results if r["verdict"] == "VALIDATED")
    flagged = len(results) - validated
    print(f"Validated {validated} sessions, flagged {flagged} for review -> {output_path}")


if __name__ == "__main__":
    main()
PYEOF
