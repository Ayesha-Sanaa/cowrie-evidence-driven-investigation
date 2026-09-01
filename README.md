# Cowrie Evidence-Driven Adversary Investigation Pipeline

A Python pipeline that turns raw honeypot logs into a real investigation — sessions, indicators, MITRE techniques, and an AI-written assessment that gets checked against the actual evidence before anyone trusts it.

The idea behind it is simple: **don't trust an AI security conclusion unless you can trace it back to real evidence.**

---

## Quick Facts

|                                    |                             |
| ---------------------------------- | --------------------------- |
| **Language**                       | Python                      |
| **Honeypot**                       | Cowrie SSH Honeypot         |
| **Environment**                    | Kali Linux (WSL)            |
| **AI Analyst**                     | Google Gemini               |
| **Attack Scenarios**               | 2 — Manual & Automated      |
| **Sessions Reconstructed**         | 2                           |
| **IOCs Extracted**                 | 9                           |
| **MITRE ATT&CK Techniques Mapped** | 7                           |
| **AI Claims Validated**            | 100% — 0 unsupported claims |


---

## Why I Built This

- Raw honeypot logs are messy — the useful stuff is buried in noise.
- An AI can easily make things up if you just hand it raw data.
- Before trusting an AI's security conclusion, you need a way to check it against what actually happened.

That last point is the whole reason this project exists.

---

## System Architecture

```
Attacker (manual or scripted)
        ↓
Cowrie SSH Honeypot
        ↓
Log Normalizer
        ↓
Session Reconstruction Engine
        ↓
IOC Extraction Engine
        ↓
MITRE ATT&CK Mapper
        ↓
AI Threat Analyst
        ↓
Evidence Validator
```

---

## Step by Step — How I Built This

### Step 1: Set up the honeypot

I deployed Cowrie, an SSH honeypot, on a Kali Linux machine. It listens on port 2222 and gives anyone who connects a fake shell that looks like a real Debian server. Every login attempt, command, and file download gets logged automatically.

<img width="1400" height="841" alt="1" src="https://github.com/user-attachments/assets/9953c8c0-7106-4bc5-8ac0-6631cf7c8905" />


### Step 2: Run a manual attack session

I connected to my own honeypot over SSH and typed commands by hand, the way a curious human attacker might: `whoami`, `uname -a`, `cat /etc/passwd`, `wget`, then exited. Natural pauses between each command.

<img width="1259" height="928" alt="2" src="https://github.com/user-attachments/assets/386debd4-cd25-414f-b943-973b77c89dd2" />

<img width="1124" height="926" alt="3" src="https://github.com/user-attachments/assets/6bf34904-880c-4a7b-b809-729691e53e99" />


### Step 3: Run an automated attack session

I wrote a small bash script using `sshpass` that logs in and fires off a whole sequence of commands instantly, one after another, with no delay — the way an automated bot would behave.

<img width="1379" height="732" alt="4" src="https://github.com/user-attachments/assets/93599e2e-d3e0-4fbb-af72-422a717c0037" />



### Step 4: Normalize the raw logs

Cowrie's raw logs are full of noise — SSH handshake details, terminal size, client version strings — mixed in with the stuff that actually matters. I wrote `normalizer.py` to go through the raw JSON and keep only the useful events (logins, commands, downloads, session close), rewritten into one clean, consistent format.

<img width="1273" height="921" alt="normal" src="https://github.com/user-attachments/assets/63b4b00b-11d6-46b9-899a-e8efeadf9e36" />

<img width="1568" height="653" alt="norshow" src="https://github.com/user-attachments/assets/2cb48de5-42be-4db9-a053-2ab6dbd1fc5d" />


### Step 5: Rebuild full sessions and classify behavior

Next I wrote `session_builder.py`. It takes all those normalized events and groups them by session ID, so instead of scattered events you get one clean object per session — who logged in, what they typed, what they downloaded, how long it took.

This script also does the behavior classification: it measures the time gap between commands. If the gaps are tiny (milliseconds), it's automated. If the gaps are long and irregular (seconds), it's a human typing.

This is where `sessions.jsonl` comes from.

<img width="1316" height="910" alt="session" src="https://github.com/user-attachments/assets/79964216-f18d-4571-9aed-775df0e0e6e7" />

<img width="1284" height="944" alt="sessionans" src="https://github.com/user-attachments/assets/b15bbd43-90e3-479a-8061-8f64b280bf98" />


### Step 6: Extract indicators (IOCs)

I wrote `ioc_extractor.py` to scan every session's commands and downloads and pull out anything worth flagging — IP addresses, URLs, file hashes, and commands that match a list of suspicious keywords like `wget`, `curl`, `chmod`. Every IOC keeps a note on exactly which command it came from.

This produces `iocs.jsonl`.

<img width="1316" height="898" alt="ioc" src="https://github.com/user-attachments/assets/82693302-94f8-472e-b942-518dd7e9923c" />

<img width="1568" height="760" alt="iocanswer" src="https://github.com/user-attachments/assets/8c3b0803-3359-4712-b1e6-1fed122ecde2" />


### Step 7: Map commands to MITRE ATT&CK

I wrote `attack_mapper.py` next. It checks every command against a fixed list of known MITRE techniques I put together myself (`whoami` → T1033, `wget` → T1105, and so on). I didn't let an AI guess these — a wrong technique ID is worse than no mapping at all.

This produces `mitre_mappings.jsonl`.

<img width="1431" height="840" alt="mittre" src="https://github.com/user-attachments/assets/51755eb0-c702-46fc-9dd1-796d0f4ce487" />

<img width="1400" height="858" alt="mittreans" src="https://github.com/user-attachments/assets/6bbc7d03-f377-4d30-918a-bcfb9da2be9d" />


### Step 8: Send the evidence to an AI for analysis

This is where `analyst.py` comes in. I packaged up everything for each session — the session data, the IOCs, the MITRE mappings — into one evidence bundle, and sent it to Google Gemini with strict instructions: only use what's in this evidence, don't assume anything, don't call something an APT unless you can actually back it up.

Gemini sends back a structured response: severity, likely objective, attack chain, a plain-English summary, and recommended actions.

This produces `ai_assessments.jsonl`.

<img width="1568" height="757" alt="ai" src="https://github.com/user-attachments/assets/b510d0a4-3542-4d61-a56d-3853817bd52b" />

<img width="1316" height="910" alt="aiupdatewrir" src="https://github.com/user-attachments/assets/2188fd33-7bd5-48c9-8611-a6bb15f6549c" />

<img width="1568" height="740" alt="airesult" src="https://github.com/user-attachments/assets/9e7cefd4-5caf-4b49-8cd7-b7efa5bdffc5" />

### Step 9: Check the AI's work

The last piece is `evidence_validator.py`. It goes back through everything the AI said and checks it against the real data — does every IP, URL, or hash it mentioned actually exist in the IOCs I extracted? Does its "automated vs interactive" call match what the timing data actually showed?

If anything doesn't match, that session gets flagged instead of blindly trusted.

This produces `evidence_validation.jsonl`, and this was the step that mattered most to me — it's the difference between "an AI wrote a report" and "an AI wrote a report that's actually been checked."

<img width="1332" height="896" alt="evidence" src="https://github.com/user-attachments/assets/b50f568f-4529-4263-ad35-5ba499a74dab" />

<img width="1338" height="896" alt="evidence result" src="https://github.com/user-attachments/assets/118bd972-5004-42d3-8cae-f3f0b5e9433a" />

---

## Results & Findings

| Session | Commands | Avg. gap between commands | Classification |
|---|---|---|---|
| Manual | 5 | ~40 sec | Interactive |
| Scripted | 9 | ~79 ms | Automated |

- 9 unique IOCs extracted
- 7 unique MITRE techniques mapped, covering a full attack chain: Discovery → Account Discovery → Network Discovery → Ingress Tool Transfer → Permission Modification → Execution
- Both sessions came back **VALIDATED**, with zero unsupported AI claims


---

## Project Limitations

- LAN-only, resource-constrained home lab. Attacker and honeypot ran on the same machine. No claim of real internet exposure or observed live campaigns — this was a controlled simulation.
- Only 2 test sessions — enough to prove the pipeline works, not enough for statistically meaningful evaluation.
- No SIEM integration yet — data lives in local JSON/JSONL files.
- No dashboard/UI — everything is viewed via terminal.

---

## Future Enhancements

- Feed pipeline output into Splunk for SPL-based searching
- A lightweight investigation dashboard
- A larger labeled dataset for real precision/recall evaluation
- Genuine network segmentation (attacker and honeypot on separate machines), resources permitting

---

## Key Takeaways

The AI part of this project was the easy part — a prompt and an API call. The real work was everywhere else: cleaning up messy logs, rebuilding sessions from scattered events, deciding what counts as a real indicator, and not trusting the AI just because it sounds confident.

AI should help with an investigation, not replace the evidence. Every conclusion here can be traced back to something real.

## References

- [Cowrie SSH Honeypot Documentation](https://cowrie.readthedocs.io/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Google Gemini API Documentation](https://ai.google.dev/gemini-api/docs)
- [Kali Linux Documentation](https://www.kali.org/docs/)
- [Python Documentation](https://docs.python.org/3/)
- [Windows Subsystem for Linux Documentation](https://learn.microsoft.com/en-us/windows/wsl/)
