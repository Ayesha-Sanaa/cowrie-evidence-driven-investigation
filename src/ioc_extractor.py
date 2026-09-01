cat > ioc_extractor.py << 'PYEOF'
import json
import re
import sys
from pathlib import Path

IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
URL_PATTERN = re.compile(r'https?://[^\s\'"]+')
DOMAIN_PATTERN = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')

SUSPICIOUS_COMMANDS = ["wget", "curl", "chmod", "nc", "netcat", "python", "perl", "bash -i", "crontab", "systemctl", "/tmp/", "base64"]


def extract_iocs_from_session(session):
    iocs = []
    sid = session["session_id"]

    # From commands
    for cmd_entry in session.get("commands", []):
        cmd = cmd_entry.get("command", "")
        if not cmd:
            continue

        for ip in IP_PATTERN.findall(cmd):
            iocs.append({"type": "ip", "value": ip, "session_id": sid, "evidence": f"Found in command: {cmd}"})

        for url in URL_PATTERN.findall(cmd):
            iocs.append({"type": "url", "value": url, "session_id": sid, "evidence": f"Found in command: {cmd}"})

        for keyword in SUSPICIOUS_COMMANDS:
            if keyword in cmd.lower():
                iocs.append({"type": "suspicious_command", "value": cmd, "session_id": sid, "evidence": f"Contains keyword: {keyword}"})
                break

    # From downloads
    for dl in session.get("downloads", []):
        if dl.get("url"):
            iocs.append({"type": "url", "value": dl["url"], "session_id": sid, "evidence": "Observed in file download event"})
        if dl.get("sha256"):
            iocs.append({"type": "sha256", "value": dl["sha256"], "session_id": sid, "evidence": f"Hash of downloaded file: {dl.get('outfile', 'unknown')}"})

    # Session source IP itself is an IOC
    if session.get("src_ip"):
        iocs.append({"type": "ip", "value": session["src_ip"], "session_id": sid, "evidence": "Source IP of session"})

    return iocs


def dedupe_iocs(iocs):
    seen = set()
    unique = []
    for ioc in iocs:
        key = (ioc["type"], ioc["value"])
        if key not in seen:
            seen.add(key)
            unique.append(ioc)
    return unique


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 ioc_extractor.py <sessions.jsonl> [output_file]")
        sys.exit(1)

    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("iocs.jsonl")

    all_iocs = []
    with open(input_path, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                session = json.loads(line)
                all_iocs.extend(extract_iocs_from_session(session))

    unique_iocs = dedupe_iocs(all_iocs)

    with open(output_path, "w") as out:
        for ioc in unique_iocs:
            out.write(json.dumps(ioc) + "\n")

    print(f"Extracted {len(all_iocs)} raw IOCs -> {len(unique_iocs)} unique IOCs written to {output_path}")


if __name__ == "__main__":
    main()
PYEOF
