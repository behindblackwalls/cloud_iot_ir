#!/usr/bin/env python3
import argparse, boto3, gzip, io, json, re, sys
from datetime import datetime, timedelta, timezone

s3 = boto3.client("s3")

def list_keys(bucket, prefix, newer_than):
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            if obj["LastModified"].astimezone(timezone.utc) >= newer_than:
                yield obj["Key"]

def stream_lines(bucket, key):
    b = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    if key.endswith(".gz"):
        with gzip.GzipFile(fileobj=io.BytesIO(b)) as g:
            for line in g.read().splitlines():
                yield line.decode("utf-8", errors="ignore")
    else:
        for line in b.decode().splitlines():
            yield line

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bucket", required=True)
    ap.add_argument("--prefix", required=True)
    ap.add_argument("--ioc", action="append", required=True, help="ip/domain/user/regex")
    ap.add_argument("--days", type=int, default=30)
    args = ap.parse_args()

    patterns = [re.compile(i, re.I) for i in args.ioc]
    newer = datetime.now(timezone.utc) - timedelta(days=args.days)

    hits = 0
    for key in list_keys(args.bucket, args.prefix, newer):
        for ln in stream_lines(args.bucket, key):
            if any(p.search(ln) for p in patterns):
                hits += 1
                try:
                    evt = json.loads(ln)
                    ts  = evt.get("eventTime") or evt.get("@timestamp") or "n/a"
                    print(json.dumps({"key": key, "ts": ts, "match": True, "snippet": ln[:300]}))
                except Exception:
                    print(json.dumps({"key": key, "match": True, "snippet": ln[:300]}))
    print(f"# total matches: {hits}", file=sys.stderr)

if __name__ == "__main__":
    main()
