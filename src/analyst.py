cat > analyst.py << 'PYEOF'
import json
import sys
import os
import time
from pathlib import Path
from dotenv import load_dotenv
from google import genai
from google.genai import errors

load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY")
if not API_KEY:
    print("ERROR: GEMINI_API_KEY not found in .env file")
    sys.exit(1)

client = genai.Client(api_key=API_KEY)

SYSTEM_PROMPT = """You are a SOC threat analyst reviewing honeypot telemetry.
You must base your assessment ONLY on the evidence provided below. Do not invent
facts, do not assume attribution, do not call anything an APT unless the evidence
clearly supports it. If evidence is insufficient for a claim, say so explicitly.

Respond ONLY with valid JSON in this exact structure, no markdown, no extra text:

{
  "severity": "low|medium|high",
  "classification": "automated_bot|interactive_attacker|unknown",
  "confidence": 0.0,
  "objective": "short phrase describing likely goal",
  "attack_chain": ["step1", "step2", "..."],
  "summary": "2-3 sentence plain-English summary of what happened",
  "recommended_actions": ["action1", "action2"]
}
"""

def build_evidence_package(session, iocs, mitre_mappings):
    session_iocs = [i for i in iocs if i.get("session_id") == session["session_id"]]
    session_mitre = [m for m in mitre_mappings if m.get("session_id") == session["session_id"]]

    package = {
        "session_id": session["session_id"],
        "src_ip": session.get("src_ip"),
        "username": session.get("username"),
        "command_count": session.get("command_count"),
        "avg_interval_ms": session.get("avg_interval_ms"),
        "behavior_classification": session.get("classification"),
        "behavior_evidence": session.get("evidence"),
        "commands": [c["command"] for c in session.get("commands", [])],
        "downloads": session.get("downloads", []),
        "iocs": session_iocs,
        "mitre_techniques": [{"id": m["technique_id"], "name": m["technique"]} for m in session_mitre],
    }
    return package


def analyze_session(evidence_package, max_retries=3):
    prompt = f"{SYSTEM_PROMPT}\n\nEVIDENCE:\n{json.dumps(evidence_package, indent=2)}"

    for attempt in range(1, max_retries + 1):
        try:
            response = client.models.generate_content(
                model="gemini-flash-latest",
                contents=prompt,
            )
            text = response.text.strip()
            if text.startswith("```"):
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]
            text = text.strip()

            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return {"error": "Failed to parse AI response as JSON", "raw_response": text}

        except errors.ServerError as e:
            print(f"  Attempt {attempt}/{max_retries} failed: {e}")
            if attempt < max_retries:
                wait = attempt * 5
                print(f"  Retrying in {wait}s...")
                time.sleep(wait)
            else:
                return {"error": "API unavailable after retries", "details": str(e)}


def main():
    if len(sys.argv) < 4:
        print("Usage: python3 analyst.py <sessions.jsonl> <iocs.jsonl> <mitre_mappings.jsonl> [output_file]")
        sys.exit(1)

    sessions_path, iocs_path, mitre_path = sys.argv[1], sys.argv[2], sys.argv[3]
    output_path = Path(sys.argv[4]) if len(sys.argv) > 4 else Path("ai_assessments.jsonl")

    with open(sessions_path) as f:
        sessions = [json.loads(line) for line in f if line.strip()]
    with open(iocs_path) as f:
        iocs = [json.loads(line) for line in f if line.strip()]
    with open(mitre_path) as f:
        mitre_mappings = [json.loads(line) for line in f if line.strip()]

    count = 0
    with open(output_path, "w") as out:
        for session in sessions:
            print(f"Analyzing session {session['session_id']}...")
            package = build_evidence_package(session, iocs, mitre_mappings)
            assessment = analyze_session(package)
            assessment["session_id"] = session["session_id"]
            out.write(json.dumps(assessment) + "\n")
            out.flush()
            count += 1

    print(f"Analyzed {count} sessions -> {output_path}")


if __name__ == "__main__":
    main()
PYEOF
