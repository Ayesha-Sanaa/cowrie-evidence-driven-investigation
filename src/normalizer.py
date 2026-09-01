cat > normalizer.py << 'PYEOF'
import json
import uuid
import sys
from pathlib import Path

EVENT_MAP = {
    "cowrie.session.connect": "connection",
    "cowrie.login.success": "login",
    "cowrie.login.failed": "login_failed",
    "cowrie.command.input": "command",
    "cowrie.session.file_download": "download",
    "cowrie.session.closed": "session_end",
}

def normalize_event(raw):
    eventid = raw.get("eventid")
    event_type = EVENT_MAP.get(eventid)
    if not event_type:
        return None

    normalized = {
        "event_id": str(uuid.uuid4()),
        "timestamp": raw.get("timestamp"),
        "session_id": raw.get("session"),
        "src_ip": raw.get("src_ip"),
        "src_port": raw.get("src_port"),
        "event_type": event_type,
        "sensor": raw.get("sensor"),
    }

    if event_type in ("login", "login_failed"):
        normalized["username"] = raw.get("username")
        normalized["password"] = raw.get("password")
    elif event_type == "command":
        normalized["command"] = raw.get("input")
    elif event_type == "download":
        normalized["url"] = raw.get("url")
        normalized["outfile"] = raw.get("outfile")
        normalized["sha256"] = raw.get("shasum")
    elif event_type == "session_end":
        normalized["duration_ms"] = raw.get("duration_ms")

    normalized["raw_event"] = raw
    return normalized


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 normalizer.py <path_to_cowrie.json> [output_file]")
        sys.exit(1)

    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("normalized_events.jsonl")

    count_in, count_out = 0, 0
    with open(input_path, "r") as infile, open(output_path, "w") as outfile:
        for line in infile:
            line = line.strip()
            if not line:
                continue
            count_in += 1
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            normalized = normalize_event(raw)
            if normalized:
                outfile.write(json.dumps(normalized) + "\n")
                count_out += 1

    print(f"Processed {count_in} raw events -> {count_out} normalized events written to {output_path}")


if __name__ == "__main__":
    main()
PYEOF
