#!/usr/bin/env python3
import argparse, os, platform, subprocess, tempfile, zipfile, shutil, json
from datetime import datetime

CMDS = {
    "Linux": [
        ("uname", ["-a"]),
        ("who", []),
        ("last", ["-n", "10"]),
        ("ps", ["aux"]),
        ("ss", ["-tunap"]),
        ("journalctl", ["-n","500"]),
    ],
    "Windows": [
        ("cmd", ["/c","systeminfo"]),
        ("cmd", ["/c","tasklist /v"]),
        ("cmd", ["/c","netstat -ano"]),
        ("wevtutil", ["epl","Security","Security.evtx"]),
        ("wevtutil", ["epl","System","System.evtx"]),
    ],
    "Darwin": [
        ("uname", ["-a"]),
        ("who", []),
        ("ps", ["aux"]),
        ("netstat", ["-anv"]),
        ("log", ["show","--predicate","eventType == logEvent","--last","1h"]),
    ],
}

def run_and_write(base, name, cmd):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=60)
    except Exception as e:
        out = str(e).encode()
    with open(os.path.join(base, f"{name}.txt"), "wb") as f:
        f.write(out)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    sysname = platform.system()
    cmds = CMDS.get(sysname, CMDS["Linux"])
    tmp = tempfile.mkdtemp(prefix="triage_")
    meta = {"system": sysname, "when": datetime.utcnow().isoformat()+"Z"}
    with open(os.path.join(tmp, "meta.json"), "w") as f:
        json.dump(meta, f)

    for label, cmd in cmds:
        run_and_write(tmp, label, cmd)

    with zipfile.ZipFile(args.out, "w", zipfile.ZIP_DEFLATED) as z:
        for root,_,files in os.walk(tmp):
            for fn in files:
                p = os.path.join(root, fn)
                z.write(p, arcname=os.path.relpath(p, tmp))
    shutil.rmtree(tmp)
    print(f"Wrote {args.out}")

if __name__ == "__main__":
    main()
