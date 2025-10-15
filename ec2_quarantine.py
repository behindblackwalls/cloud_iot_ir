#!/usr/bin/env python3
import argparse, os, boto3, json
from botocore.exceptions import ClientError

QUAR_SG = os.getenv("QUARANTINE_SG_ID")
TAG_PREV = "IR_PreviousSGs"
TAG_STATE = "IR_State"

ec2 = boto3.client("ec2")

def get_enis(instance_id):
    res = ec2.describe_instances(InstanceIds=[instance_id])
    enis = []
    for r in res["Reservations"]:
        for i in r["Instances"]:
            for eni in i.get("NetworkInterfaces", []):
                enis.append(eni)
    return enis

def tag_instance(instance_id, kv):
    ec2.create_tags(Resources=[instance_id], Tags=[{"Key": k, "Value": v} for k,v in kv.items()])

def quarantine(instance_id):
    if not QUAR_SG:
        raise SystemExit("Set QUARANTINE_SG_ID")

    enis = get_enis(instance_id)
    prev = {}
    for eni in enis:
        eni_id = eni["NetworkInterfaceId"]
        groups = [g["GroupId"] for g in eni["Groups"]]
        prev[eni_id] = groups
        ec2.modify_network_interface_attribute(NetworkInterfaceId=eni_id, Groups=[QUAR_SG])

    tag_instance(instance_id, {TAG_PREV: json.dumps(prev), TAG_STATE: "quarantined"})
    print(f"Quarantined {instance_id}; previous groups saved to tag {TAG_PREV}")

def restore(instance_id):
    res = ec2.describe_instances(InstanceIds=[instance_id])
    tags = {t["Key"]: t["Value"] for t in res["Reservations"][0]["Instances"][0].get("Tags", [])}
    prev = json.loads(tags.get(TAG_PREV, "{}"))
    if not prev:
        raise SystemExit("No previous SGs stored; cannot restore.")

    for eni_id, groups in prev.items():
        try:
            ec2.modify_network_interface_attribute(NetworkInterfaceId=eni_id, Groups=groups)
        except ClientError as e:
            print(f"Failed restoring ENI {eni_id}: {e}")

    tag_instance(instance_id, {TAG_STATE: "restored"})
    print(f"Restored {instance_id} to previous SGs.")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["quarantine","restore"])
    ap.add_argument("instance_id")
    args = ap.parse_args()
    {"quarantine": quarantine, "restore": restore}[args.action](args.instance_id)
