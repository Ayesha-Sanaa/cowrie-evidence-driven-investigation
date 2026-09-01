cat > session_builder.py << 'PYEOF'
import json
import sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict

def parse_ts(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))

def build_sessions(events):
    sessions = defaultdict(lambda: {
        "session_id": None,
        "src_ip": None,
        "start_time": None,
        "end_time": None,
        "duration_ms": None,
        "username": None,
        "password": None,
        "login_success": False,
        "commands": [],
        "downloads": [],
    })

    for e in events:
        sid = e["session_id"]
        s = sessions[sid]
        s["session_id"] = sid
        s["src_ip"] = e.get("src_ip")

        if e["event_type"] == "connection":
            s["start_time"] = e["timestamp"]
        elif e["event_type"] == "login":
            s["username"] = e.get("username")
            s["password"] = e.get("password")
            s["login_success"] = True
        elif e["event_type"] == "command":
            s["commands"].append({
                "timestamp": e["timestamp"],
                "command": e.get("command"),
            })
        elif e["event_type"] == "download":
            s["downloads"].append({
                "url": e.get("url"),
                "sha256": e.get("sha256"),
                "outfile": e.get("outfile"),
            })
        elif e["event_type"] == "session_end":
            s["end_time"] = e["timestamp"]
            s["duration_ms"] = e.get("duration_ms")

    return sessions


def compute_behavior(session):
    cmds = session["commands"]
    if len(cmds) < 2:
        session["command_count"] = len(cmds)
        session["avg_interval_ms"] = None
        session["classification"] = "insufficient_data"
        session["evidence"] = "Fewer than 2 commands observed"
        return session

    intervals = []
    for i in range(1, len(cmds)):
        t1 = parse_ts(cmds[i - 1]["timestamp"])
        t2 = parse_ts(cmds[i]["timestamp"])
        intervals.append((t2 - t1).total_seconds() * 1000)

    avg_interval = sum(intervals) / len(intervals)
    session["command_count"] = len(cmds)
    session["avg_interval_ms"] = round(avg_interval, 2)

    if avg_interval < 500:
        session["classification"] = "automated"
        session["evidence"] = f"{len(cmds)} commands executed with average interval of {round(avg_interval,2)}ms"
    elif avg_interval > 3000:
        session["classification"] = "interactive"
        session["evidence"] = f"{len(cmds)} commands executed with average interval of {round(avg_interval,2)}ms"
    else:
        session["classification"] = "ambiguous"
        session["evidence"] = f"Average interval {round(avg_interval,2)}ms falls in ambiguous range"

    return session


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 session_builder.py <normalized_events.jsonl> [output_file]")
        sys.exit(1)

    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("sessions.jsonl")

    events = []
    with open(input_path, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))

    sessions = build_sessions(events)

    with open(output_path, "w") as out:
        for sid, s in sessions.items():
            s = compute_behavior(s)
            out.write(json.dumps(s) + "\n")

    print(f"Built {len(sessions)} sessions -> written to {output_path}")


if __name__ == "__main__":
    main()
PYEOF
