cat > attack_mapper.py << 'PYEOF'
import json
import sys
from pathlib import Path

# Controlled mapping: command pattern -> MITRE technique
# Keep this evidence-based and conservative - no guessing.
MITRE_MAPPINGS = [
    {"pattern": "whoami", "technique_id": "T1033", "technique": "System Owner/User Discovery"},
    {"pattern": "uname", "technique_id": "T1082", "technique": "System Information Discovery"},
    {"pattern": "id", "technique_id": "T1033", "technique": "System Owner/User Discovery"},
    {"pattern": "ifconfig", "technique_id": "T1016", "technique": "System Network Configuration Discovery"},
    {"pattern": "ip addr", "technique_id": "T1016", "technique": "System Network Configuration Discovery"},
    {"pattern": "netstat", "technique_id": "T1049", "technique": "System Network Connections Discovery"},
    {"pattern": "ss ", "technique_id": "T1049", "technique": "System Network Connections Discovery"},
    {"pattern": "cat /etc/passwd", "technique_id": "T1087", "technique": "Account Discovery"},
    {"pattern": "wget", "technique_id": "T1105", "technique": "Ingress Tool Transfer"},
    {"pattern": "curl", "technique_id": "T1105", "technique": "Ingress Tool Transfer"},
    {"pattern": "chmod +x", "technique_id": "T1222", "technique": "File and Directory Permissions Modification"},
    {"pattern": "crontab", "technique_id": "T1053.003", "technique": "Scheduled Task/Job: Cron"},
    {"pattern": "systemctl", "technique_id": "T1543.002", "technique": "Create or Modify System Process: Systemd Service"},
    {"pattern": "./", "technique_id": "T1059.004", "technique": "Command and Scripting Interpreter: Unix Shell"},
]


def map_command_to_techniques(command):
    if not command:
        return []
    matches = []
    cmd_lower = command.lower()
    for rule in MITRE_MAPPINGS:
        if rule["pattern"].lower() in cmd_lower:
            matches.append({
                "technique_id": rule["technique_id"],
                "technique": rule["technique"],
                "matched_pattern": rule["pattern"],
                "evidence": f"Command '{command}' matched pattern '{rule['pattern']}'",
            })
    return matches


def map_session(session):
    session_techniques = []
    for cmd_entry in session.get("commands", []):
        cmd = cmd_entry.get("command", "")
        if len(cmd) > 200:  # skip noise/garbage entries
            continue
        matches = map_command_to_techniques(cmd)
        for m in matches:
            m["session_id"] = session["session_id"]
            m["command"] = cmd
            m["timestamp"] = cmd_entry.get("timestamp")
            session_techniques.append(m)
    return session_techniques


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 attack_mapper.py <sessions.jsonl> [output_file]")
        sys.exit(1)

    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("mitre_mappings.jsonl")

    all_techniques = []
    with open(input_path, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                session = json.loads(line)
                all_techniques.extend(map_session(session))

    with open(output_path, "w") as out:
        for t in all_techniques:
            out.write(json.dumps(t) + "\n")

    unique_techniques = set(t["technique_id"] for t in all_techniques)
    print(f"Mapped {len(all_techniques)} technique observations ({len(unique_techniques)} unique techniques) -> {output_path}")


if __name__ == "__main__":
    main()
PYEOF
