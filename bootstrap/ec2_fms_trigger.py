"""Launch a minimal EC2 instance to make Firewall Manager build its security groups.

Firewall Manager security group policies only replicate their security groups
into a VPC once there is an in-scope resource there. This tool puts the
smallest, cheapest possible instance into a VPC to trigger that:

  * latest Amazon Linux 2023 AMI (resolved from the public SSM parameter)
  * cheapest available instance type in the chosen AZ (t4g.nano -> t3a.nano -> t3.nano -> t2.nano)
  * no instance profile, no key pair, no public IP, IMDSv2 required, encrypted gp3 root
  * a dedicated security group with NO ingress and NO egress rules

Subcommands:
  create   launch the instance (idempotent: skips if one already exists in the VPC)
  status   list instances / security groups created by this tool
  destroy  terminate the instance(s) and delete the security group(s)

Examples:
  python -m bootstrap.ec2_fms_trigger create --profile prod-admin --region us-east-1
  python -m bootstrap.ec2_fms_trigger create -p dev --vpc-id vpc-0123456789abcdef0 --wait
  python -m bootstrap.ec2_fms_trigger status -p dev
  python -m bootstrap.ec2_fms_trigger destroy -p dev --vpc-id vpc-0123456789abcdef0 --yes
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Any

from botocore.exceptions import ClientError

from .common import (
    TOOL_TAG_KEY,
    BootstrapError,
    TagConfig,
    add_common_args,
    caller_identity,
    confirm,
    make_session,
    run_cli,
    setup_logging,
    tag_value,
)

log = logging.getLogger("bootstrap.ec2_fms_trigger")

TOOL_NAME = "ec2-fms-trigger"
DEFAULT_SG_NAME = "fms-trigger-deny-all"

# Cheapest first (us-east-1 on-demand Linux, USD/hr):
#   t4g.nano 0.0042 | t3a.nano 0.0047 | t3.nano 0.0052 | t2.nano 0.0058
DEFAULT_INSTANCE_TYPES = ["t4g.nano", "t3a.nano", "t3.nano", "t2.nano"]

AL2023_SSM_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-{arch}"
LIVE_STATES = ["pending", "running", "stopping", "stopped"]


# --------------------------------------------------------------------------- #
# Lookups
# --------------------------------------------------------------------------- #
def resolve_vpc(ec2, vpc_id: str | None) -> str:
    if vpc_id:
        try:
            ec2.describe_vpcs(VpcIds=[vpc_id])
        except ClientError as exc:
            raise BootstrapError(f"VPC {vpc_id} not found: {exc}") from exc
        return vpc_id
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "is-default", "Values": ["true"]}])["Vpcs"]
    if not vpcs:
        raise BootstrapError("No default VPC in this region; pass --vpc-id or --subnet-id.")
    return vpcs[0]["VpcId"]


def list_subnets(ec2, vpc_id: str) -> list[dict[str, Any]]:
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "state", "Values": ["available"]}]
    )["Subnets"]
    if not subnets:
        raise BootstrapError(f"VPC {vpc_id} has no available subnets.")
    return sorted(subnets, key=lambda s: (s["AvailabilityZone"], s["SubnetId"]))


def offered_azs(ec2, instance_type: str) -> set[str]:
    resp = ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [instance_type]}],
    )
    return {o["Location"] for o in resp["InstanceTypeOfferings"]}


def choose_placement(ec2, subnets: list[dict[str, Any]], candidates: list[str]) -> tuple[dict[str, Any], str]:
    """Return (subnet, instance_type) for the cheapest type offered in any subnet's AZ."""
    for itype in candidates:
        azs = offered_azs(ec2, itype)
        for subnet in subnets:
            if subnet["AvailabilityZone"] in azs:
                return subnet, itype
        log.debug("%s not offered in any candidate AZ", itype)
    raise BootstrapError(
        f"None of {candidates} are offered in AZs "
        f"{sorted({s['AvailabilityZone'] for s in subnets})}."
    )


def instance_arch(ec2, instance_type: str) -> str:
    info = ec2.describe_instance_types(InstanceTypes=[instance_type])["InstanceTypes"][0]
    archs = info["ProcessorInfo"]["SupportedArchitectures"]
    for arch in ("arm64", "x86_64"):
        if arch in archs:
            return arch
    raise BootstrapError(f"{instance_type}: unsupported architectures {archs}")


def latest_al2023_ami(ssm, ec2, arch: str) -> dict[str, Any]:
    name = AL2023_SSM_PARAM.format(arch=arch)
    try:
        image_id = ssm.get_parameter(Name=name)["Parameter"]["Value"]
    except ClientError as exc:
        raise BootstrapError(f"Could not read SSM parameter {name}: {exc}") from exc
    images = ec2.describe_images(ImageIds=[image_id])["Images"]
    if not images:
        raise BootstrapError(f"AMI {image_id} (from {name}) not found")
    return images[0]


# --------------------------------------------------------------------------- #
# Security group
# --------------------------------------------------------------------------- #
def find_tool_sgs(ec2, vpc_id: str | None = None) -> list[dict[str, Any]]:
    filters = [{"Name": f"tag:{TOOL_TAG_KEY}", "Values": [TOOL_NAME]}]
    if vpc_id:
        filters.append({"Name": "vpc-id", "Values": [vpc_id]})
    return ec2.describe_security_groups(Filters=filters)["SecurityGroups"]


def strip_rules(ec2, sg: dict[str, Any]) -> None:
    """Remove every ingress/egress rule so the SG permits nothing."""
    if sg.get("IpPermissions"):
        ec2.revoke_security_group_ingress(GroupId=sg["GroupId"], IpPermissions=sg["IpPermissions"])
        log.info("Revoked %d ingress rule(s) from %s", len(sg["IpPermissions"]), sg["GroupId"])
    if sg.get("IpPermissionsEgress"):
        ec2.revoke_security_group_egress(GroupId=sg["GroupId"], IpPermissions=sg["IpPermissionsEgress"])
        log.info("Revoked %d egress rule(s) from %s", len(sg["IpPermissionsEgress"]), sg["GroupId"])


def ensure_security_group(ec2, vpc_id: str, name: str, tags: TagConfig) -> str:
    existing = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": [name]}]
    )["SecurityGroups"]
    if existing:
        sg = existing[0]
        if tag_value(sg.get("Tags"), TOOL_TAG_KEY) != TOOL_NAME:
            raise BootstrapError(
                f"Security group '{name}' ({sg['GroupId']}) exists in {vpc_id} but was not "
                f"created by this tool; pass a different --sg-name."
            )
        log.info("Reusing security group %s (%s)", sg["GroupId"], name)
        strip_rules(ec2, sg)
        return sg["GroupId"]

    resp = ec2.create_security_group(
        GroupName=name,
        Description="Deny-all placeholder for Firewall Manager trigger (no ingress, no egress)",
        VpcId=vpc_id,
        TagSpecifications=[{
            "ResourceType": "security-group",
            "Tags": tags.tag_list("security_group", {TOOL_TAG_KEY: TOOL_NAME}),
        }],
    )
    sg_id = resp["GroupId"]
    log.info("Created security group %s (%s)", sg_id, name)
    # New SGs come with an allow-all egress rule; remove it.
    sg = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
    strip_rules(ec2, sg)
    return sg_id


# --------------------------------------------------------------------------- #
# Instances
# --------------------------------------------------------------------------- #
def find_tool_instances(ec2, vpc_id: str | None = None, states=LIVE_STATES) -> list[dict[str, Any]]:
    filters = [
        {"Name": f"tag:{TOOL_TAG_KEY}", "Values": [TOOL_NAME]},
        {"Name": "instance-state-name", "Values": list(states)},
    ]
    if vpc_id:
        filters.append({"Name": "vpc-id", "Values": [vpc_id]})
    out = []
    for page in ec2.get_paginator("describe_instances").paginate(Filters=filters):
        for res in page["Reservations"]:
            out.extend(res["Instances"])
    return out


def build_run_instances_params(*, ami: dict[str, Any], instance_type: str, subnet_id: str,
                               sg_id: str, tags: TagConfig) -> dict[str, Any]:
    tool_tag = {TOOL_TAG_KEY: TOOL_NAME}
    root_name = ami["RootDeviceName"]
    root_ebs = next(
        (m["Ebs"] for m in ami.get("BlockDeviceMappings", []) if m.get("DeviceName") == root_name and "Ebs" in m),
        {},
    )
    ebs = {"VolumeType": "gp3", "Encrypted": True, "DeleteOnTermination": True}
    if root_ebs.get("VolumeSize"):
        ebs["VolumeSize"] = root_ebs["VolumeSize"]

    return {
        "ImageId": ami["ImageId"],
        "InstanceType": instance_type,
        "MinCount": 1,
        "MaxCount": 1,
        "NetworkInterfaces": [{
            "DeviceIndex": 0,
            "SubnetId": subnet_id,
            "Groups": [sg_id],
            "AssociatePublicIpAddress": False,
            "DeleteOnTermination": True,
        }],
        "BlockDeviceMappings": [{"DeviceName": root_name, "Ebs": ebs}],
        "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled", "HttpPutResponseHopLimit": 1},
        "CreditSpecification": {"CpuCredits": "standard"},
        "InstanceInitiatedShutdownBehavior": "stop",
        "TagSpecifications": [
            {"ResourceType": "instance", "Tags": tags.tag_list("instance", tool_tag)},
            {"ResourceType": "volume", "Tags": tags.tag_list("volume", tool_tag)},
            {"ResourceType": "network-interface", "Tags": tags.tag_list("network_interface", tool_tag)},
        ],
    }


# --------------------------------------------------------------------------- #
# Subcommands
# --------------------------------------------------------------------------- #
def cmd_create(args, session, ident) -> int:
    ec2 = session.client("ec2")
    ssm = session.client("ssm")

    if args.subnet_id:
        subnet = ec2.describe_subnets(SubnetIds=[args.subnet_id])["Subnets"][0]
        if args.vpc_id and args.vpc_id != subnet["VpcId"]:
            raise BootstrapError(f"Subnet {args.subnet_id} is in {subnet['VpcId']}, not {args.vpc_id}")
        vpc_id, subnets = subnet["VpcId"], [subnet]
    else:
        vpc_id = resolve_vpc(ec2, args.vpc_id)
        subnets = list_subnets(ec2, vpc_id)

    existing = find_tool_instances(ec2, vpc_id)
    if existing and not args.force:
        for i in existing:
            log.info("Already present: %s (%s, %s) in %s",
                     i["InstanceId"], i["InstanceType"], i["State"]["Name"], vpc_id)
        log.info("Nothing to do (use --force to launch another).")
        return 0

    candidates = [args.instance_type] if args.instance_type else DEFAULT_INSTANCE_TYPES
    subnet, itype = choose_placement(ec2, subnets, candidates)
    arch = instance_arch(ec2, itype)
    ami = latest_al2023_ami(ssm, ec2, arch)

    tags = TagConfig.load(args.tags_config, {
        "account_id": ident["account_id"],
        "region": session.region_name,
        "profile": args.profile or "default",
        "vpc_id": vpc_id,
    })

    log.info("Account %s / %s / %s", ident["account_id"], session.region_name, vpc_id)
    log.info("Subnet  %s (%s)", subnet["SubnetId"], subnet["AvailabilityZone"])
    log.info("Type    %s (%s)", itype, arch)
    log.info("AMI     %s (%s)", ami["ImageId"], ami.get("Name", "?"))

    if args.dry_run:
        # Validate permissions/parameters with EC2's DryRun without creating anything.
        params = build_run_instances_params(ami=ami, instance_type=itype, subnet_id=subnet["SubnetId"],
                                            sg_id="sg-00000000000000000", tags=tags)
        params["NetworkInterfaces"][0].pop("Groups")
        try:
            ec2.run_instances(DryRun=True, **params)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DryRunOperation":
                raise
        log.info("Dry run OK: RunInstances would succeed (security group '%s' not created).", args.sg_name)
        return 0

    sg_id = ensure_security_group(ec2, vpc_id, args.sg_name, tags)
    params = build_run_instances_params(ami=ami, instance_type=itype, subnet_id=subnet["SubnetId"],
                                        sg_id=sg_id, tags=tags)
    inst = ec2.run_instances(**params)["Instances"][0]
    iid = inst["InstanceId"]
    log.info("Launched %s", iid)

    if args.wait:
        log.info("Waiting for %s to be running...", iid)
        ec2.get_waiter("instance_running").wait(InstanceIds=[iid])
        log.info("%s is running", iid)

    print(iid)
    return 0


def cmd_status(args, session, ident) -> int:
    ec2 = session.client("ec2")
    instances = find_tool_instances(ec2, args.vpc_id)
    sgs = find_tool_sgs(ec2, args.vpc_id)
    print(f"Account {ident['account_id']}  Region {session.region_name}")
    print(f"Instances ({len(instances)}):")
    for i in instances:
        print(f"  {i['InstanceId']}  {i['InstanceType']:<9} {i['State']['Name']:<9} "
              f"{i.get('VpcId', '-')}  {i.get('SubnetId', '-')}  {i.get('ImageId')}")
    print(f"Security groups ({len(sgs)}):")
    for sg in sgs:
        n_in, n_out = len(sg.get("IpPermissions", [])), len(sg.get("IpPermissionsEgress", []))
        print(f"  {sg['GroupId']}  {sg['GroupName']:<24} {sg['VpcId']}  ingress={n_in} egress={n_out}")
    return 0


def cmd_destroy(args, session, ident) -> int:
    ec2 = session.client("ec2")
    instances = find_tool_instances(ec2, args.vpc_id)
    sgs = find_tool_sgs(ec2, args.vpc_id)
    if not instances and not sgs:
        log.info("Nothing to destroy.")
        return 0

    scope = args.vpc_id or "ALL VPCs"
    print(f"Account {ident['account_id']} / {session.region_name} / {scope}:")
    for i in instances:
        print(f"  terminate {i['InstanceId']} ({i['InstanceType']}, {i['State']['Name']})")
    for sg in sgs:
        print(f"  delete    {sg['GroupId']} ({sg['GroupName']}, {sg['VpcId']})")
    if not confirm("Proceed?", args.yes):
        log.info("Aborted.")
        return 1

    if instances:
        ids = [i["InstanceId"] for i in instances]
        ec2.terminate_instances(InstanceIds=ids)
        log.info("Terminating %s; waiting...", ", ".join(ids))
        ec2.get_waiter("instance_terminated").wait(InstanceIds=ids)
        log.info("Terminated.")

    failed = 0
    for sg in sgs:
        try:
            ec2.delete_security_group(GroupId=sg["GroupId"])
            log.info("Deleted %s", sg["GroupId"])
        except ClientError as exc:
            failed += 1
            log.error("Could not delete %s: %s", sg["GroupId"], exc)
    return 1 if failed else 0


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ec2_fms_trigger",
        description=__doc__.split("\n\n")[0],
        epilog="Examples:" + __doc__.split("Examples:", 1)[1],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("create", help="Launch the trigger instance")
    add_common_args(p)
    p.add_argument("--vpc-id", help="Target VPC (default: the region's default VPC)")
    p.add_argument("--subnet-id", help="Target subnet (default: first subnet whose AZ offers the cheapest type)")
    p.add_argument("--instance-type", help=f"Force an instance type (default: cheapest of {DEFAULT_INSTANCE_TYPES})")
    p.add_argument("--sg-name", default=DEFAULT_SG_NAME, help=f"Security group name (default: {DEFAULT_SG_NAME})")
    p.add_argument("--wait", action="store_true", help="Wait until the instance is running")
    p.add_argument("--force", action="store_true", help="Launch even if one already exists in the VPC")
    p.add_argument("--dry-run", action="store_true", help="Resolve everything and run an EC2 DryRun; create nothing")
    p.set_defaults(func=cmd_create)

    p = sub.add_parser("status", help="Show resources created by this tool")
    add_common_args(p)
    p.add_argument("--vpc-id", help="Limit to one VPC")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("destroy", help="Terminate instance(s) and delete the security group(s)")
    add_common_args(p)
    p.add_argument("--vpc-id", help="Limit to one VPC (default: all VPCs in the region)")
    p.add_argument("--yes", "-y", action="store_true", help="Do not prompt for confirmation")
    p.set_defaults(func=cmd_destroy)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(args.verbose)
    session = make_session(args.profile, args.region)
    ident = caller_identity(session)
    log.debug("Caller: %s", ident["arn"])
    return args.func(args, session, ident)


if __name__ == "__main__":
    sys.exit(run_cli(main))
