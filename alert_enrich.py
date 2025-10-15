#!/usr/bin/env python3
"""
Enrich a SIEM alert with CMDB + Threat Intel and post a triage card to Slack.
"""
import argparse, json, os, sys, requests
from datetime import datetime, timezone

TIMEOUT = 5
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK")
CMDB_URL = os.getenv("CMDB_URL")          # e.g., https://cmdb.internal/api
TI_URL   = os.getenv("TI_URL")            # e.g., https://ti.internal/api

def http_get(url):
    r = requests.get(url, timeout=TIMEOUT)
    r.raise_for_status()
    return r.json()

def get_asset(host_id: str) -> dict:
    if not CMDB_URL:
        return {}
    return http_get(f"{CMDB_URL}/assets/{host_id}")

def ip_reputation(ip: str) -> dict:
    if not TI_URL:
        return {}
    return http_get(f"{TI_URL}/reputation/ip/{ip}")

def score(alert: dict, intel: dict, asset: dict) -> int:
    s = 0
    if intel.get("malicious"): s += 50
    if alert.get("failed_logins", 0) > 20: s += 15
    if asset.get("tier") in {"prod","tier1"}: s += 20
    if alert.get("rule_sev") == "high": s += 10
    return min(100, s)

def slack_post(text: str):
    if not SLACK_WEBHOOK:
        print("[dry-run] Slack message:\n" + text)
        return
    requests.post(SLACK_WEBHOOK, json={"text": text}, timeout=TIMEOUT)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--alert", required=True, help="path to alert JSON or '-' for stdin")
    p.add_argument("--post", action="store_true", help="actually post to Slack")
    args = p.parse_args()

    data = json.load(sys.stdin if args.alert == "-" else open(args.alert))
    asset = get_asset(data.get("host_id",""))
    intel = ip_reputation(data.get("src_ip",""))

    sev = score(data, intel, asset)
    owner = asset.get("owner_email","unknown")
    hostn = asset.get("hostname", data.get("host_id","unknown"))
    intel_cls = intel.get("classification", "unknown")
    ts = datetime.now(timezone.utc).isoformat()

    msg = (
        f"*New Security Alert* ({sev}/100)\n"
        f"• Rule: `{data.get('rule_name','unknown')}` at {ts}\n"
        f"• Host: `{hostn}`  Owner: {owner}  Tier: {asset.get('tier','n/a')}\n"
        f"• Src IP: `{data.get('src_ip','?')}`  TI: *{intel_cls}*\n"
        f"• Observed: failed_logins={data.get('failed_logins',0)} target_is_prod={asset.get('tier')=='prod'}\n"
        f"Suggested next: quarantine? rotate creds? open IR ticket?"
    )
    if args.post:
        slack_post(msg)
    else:
        print(msg)

if __name__ == "__main__":
    main()
