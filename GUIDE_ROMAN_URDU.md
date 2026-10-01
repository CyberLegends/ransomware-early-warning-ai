# Ransomware Early Warning AI — Roman Urdu guide

Yeh Cyber Legends ka defensive reference project hai. Is ka maqsad exported telemetry mein early warning signals ko correlate karna aur analyst ko evidence ke saath investigation plan dena hai. Yeh future attack ki guaranteed prediction ya live ransomware protection product nahi hai.

## Pehla run

1. Python 3.11 ya newer install karein aur version check karein: `python --version`. Windows par `py -3` bhi use kar sakte hain.
2. GitHub repository se **Code → Download ZIP** karein, extract karein aur us folder mein terminal kholein jahan `README.md` maujood hai.
3. Demo run karein:

```bash
python -m ransomware_guard demo --out output/demo
```

4. `output/demo/report.html` ko browser mein open karein. Finance ka synthetic case 100/100 aur office ka benign case 0/100 hona chahiye.
5. Tests run karein:

```bash
python -m unittest discover -s tests -v
```

Initial code release ke 55 offline tests pass hue. Yeh real-world detection accuracy ka percentage nahi hai.

## AI aur agent ka farq

Default mode mein agent timeline, baseline aur playbook check karke deterministic plan banata hai. Is ko report mein `offline_rule_agent` kaha gaya hai.

Generative AI ke liye apna installed local Ollama model use karein:

```bash
python -m ransomware_guard demo --model YOUR_INSTALLED_LOCAL_MODEL --out output/ai-demo
```

Model agla allowed investigation tool choose karta hai, us ka result dekhta hai aur phir agla step ya final draft banata hai. Agent ko arbitrary command, URL, file path ya doosre host ka access nahi diya gaya. Model ka text analyst ko verify karna hota hai. Live Ollama inference authoring environment mein test nahi hua; mocked responses ke saath adapter aur agent boundaries test hui hain.

## Apni telemetry ka istemal

Telemetry JSONL file mein honi chahiye: har line par aik normalized event. Timestamps timezone ke saath dein, event ID stable rakhein aur host/actor ki mapping verify karein. Full schema aur source mapping [IMPLEMENTATION.md](IMPLEMENTATION.md) mein hai. Real evidence public GitHub par upload na karein.

```bash
python -m ransomware_guard analyze --input your-normalized-export.jsonl --out output/your-lab
```

## Human review aur simulation

Report parhein, host aur evidence check karein, phir proposed response ka reviewed record banayein:

```bash
python -m ransomware_guard approve --report output/demo/report.json --case LAB-FINANCE-01 --reviewer lab-reviewer --reviewed --out output/approval.json
python -m ransomware_guard simulate-response --report output/demo/report.json --approval output/approval.json --ledger output/simulation-ledger.json --out output/simulation.json
```

Is se endpoint isolate, account disable ya backup modify nahi hota. Sirf simulation result banta hai. Reviewed record default 15 minutes mein expire hota hai aur wohi ledger dobara use ko reject karta hai. Yeh editable lab files hain; production mein authenticated authorization service alag banana hogi.

## Deployment ka agla stage

Read-only pilot ke liye real telemetry adapter, source authentication, durable correlation, held-out validation data, false-positive measurement aur incident ownership chahiye. Full implementation phases aur troubleshooting [IMPLEMENTATION.md](IMPLEMENTATION.md) mein hain.
