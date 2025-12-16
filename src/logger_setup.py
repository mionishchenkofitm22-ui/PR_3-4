import json, time
from pathlib import Path

LOG_PATH = Path("logs/app.jsonl")

def log_event(event: str, **fields):
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "ts": int(time.time()),
        "event": event,
        **fields,
    }
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
