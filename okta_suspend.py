#!/usr/bin/env python3
import argparse, os, requests

OKTA = os.getenv("OKTA_ORG")
TOK  = os.getenv("OKTA_TOKEN")
HDRS = {"Authorization": f"SSWS {TOK}", "Accept": "application/json"}

def ensure():
    if not OKTA or not TOK:
        raise SystemExit("Set OKTA_ORG and OKTA_TOKEN")

def revoke_sessions(user_id):
    requests.delete(f"{OKTA}/api/v1/users/{user_id}/sessions", headers=HDRS, timeout=5)

def suspend(user_id):
    ensure(); revoke_sessions(user_id)
    r = requests.post(f"{OKTA}/api/v1/users/{user_id}/lifecycle/suspend", headers=HDRS, timeout=5)
    r.raise_for_status(); print("Suspended.")

def unsuspend(user_id):
    ensure()
    r = requests.post(f"{OKTA}/api/v1/users/{user_id}/lifecycle/unsuspend", headers=HDRS, timeout=5)
    r.raise_for_status(); print("Unsuspended.")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["suspend","unsuspend"])
    ap.add_argument("user_id")
    a = ap.parse_args()
    {"suspend": suspend, "unsuspend": unsuspend}[a.action](a.user_id)
