#!/usr/bin/env python3
import argparse, boto3, json, hashlib, time
from botocore.exceptions import ClientError

def cloudtrail_status():
    ct = boto3.client("cloudtrail")
    trails = ct.describe_trails(includeShadowTrails=False)["trailList"]
    status = []
    for t in trails:
        s = ct.get_trail_status(Name=t["Name"])
        status.append({"name": t["Name"], "isMultiRegion": t.get("IsMultiRegionTrail", False),
                       "logging": s.get("IsLogging", False)})
    return status

def s3_default_encryption(buckets):
    s3 = boto3.client("s3")
    results = {}
    for b in buckets:
        try:
            enc = s3.get_bucket_encryption(Bucket=b)
            rules = enc["ServerSideEncryptionConfiguration"]["Rules"]
            results[b] = {"encrypted": True, "rules": rules}
        except ClientError:
            results[b] = {"encrypted": False}
    return results

def kms_key_rotation():
    kms = boto3.client("kms")
    keys = kms.list_keys(Limit=1000)["Keys"]
    out = []
    for k in keys:
        desc = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
        rot = kms.get_key_rotation_status(KeyId=k["KeyId"])
        out.append({"keyId": k["KeyId"], "enabled": desc["Enabled"], "rotationEnabled": rot["KeyRotationEnabled"]})
    return out

def iam_password_policy():
    iam = boto3.client("iam")
    try:
        p = iam.get_account_password_policy()["PasswordPolicy"]
        return p
    except ClientError:
        return {"policy": "none"}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--buckets", required=True, help="comma-separated")
    ap.add_argument("--outfile", required=True)
    args = ap.parse_args()

    buckets = [b.strip() for b in args.buckets.split(",") if b.strip()]
    evidence = {
        "when": int(time.time()),
        "cloudtrail": cloudtrail_status(),
        "s3_encryption": s3_default_encryption(buckets),
        "kms_rotation": kms_key_rotation(),
        "iam_password_policy": iam_password_policy(),
    }
    blob = json.dumps(evidence, indent=2, sort_keys=True).encode()
    sha = hashlib.sha256(blob).hexdigest()
    envelope = {"sha256": sha, "evidence": evidence}

    with open(args.outfile, "w") as f:
        json.dump(envelope, f, indent=2)
    print(f"Wrote {args.outfile} (sha256={sha})")

if __name__ == "__main__":
    main()
