#!/usr/bin/env python3
import argparse, json, datetime

def parse_ts(ts):
    try:
        return datetime.datetime.fromisoformat(ts.replace("Z","+00:00"))
    except Exception:
        return datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inf", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    events = []
    with open(args.inf) as f:
        for line in f:
            if not line.strip(): continue
            evt = json.loads(line)
            evt["_dt"] = parse_ts(evt.get("ts","1970-01-01T00:00:00Z"))
            events.append(evt)
    events.sort(key=lambda e: e["_dt"])

    with open(args.out, "w") as f:
        f.write("# Incident Timeline\n\n")
        for e in events:
            t = e["_dt"].isoformat()
            f.write(f"- **{t}** — *{e.get('actor','?')}* ({e.get('src','?')}): {e.get('msg','')}\n")
    print(f"Wrote {args.out}")

if __name__ == "__main__":
    main()
