import os

import boto3
import pytest
from moto import mock_aws

from bootstrap import ec2_fms_trigger as tool
from bootstrap.common import TOOL_TAG_KEY, BootstrapError, TagConfig, tag_value

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def aws_env(monkeypatch):
    for k in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    with mock_aws():
        yield


@pytest.fixture
def ec2():
    return boto3.client("ec2", REGION)


def run(*argv):
    return tool.main(list(argv) + ["--region", REGION])


def test_tag_config_merge_and_substitution(tmp_path):
    cfg = tmp_path / "t.yaml"
    cfg.write_text("common: {A: '1', B: '2'}\nresources:\n  instance: {B: x, Name: 'n-${vpc_id}'}\n")
    tc = TagConfig.load(cfg, {"vpc_id": "vpc-1"})
    assert tc.tags_for("instance") == {"A": "1", "B": "x", "Name": "n-vpc-1"}
    assert tc.tags_for("volume") == {"A": "1", "B": "2"}


def test_tag_config_rejects_aws_prefix(tmp_path):
    cfg = tmp_path / "t.yaml"
    cfg.write_text("common: {'aws:foo': bar}\n")
    with pytest.raises(BootstrapError):
        TagConfig.load(cfg)


def test_create_launches_deny_all_instance(ec2, capsys):
    assert run("create") == 0
    iid = capsys.readouterr().out.strip().splitlines()[-1]

    inst = ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]
    assert inst["InstanceType"] == "t4g.nano"
    assert "IamInstanceProfile" not in inst
    assert "KeyName" not in inst
    assert tag_value(inst["Tags"], TOOL_TAG_KEY) == tool.TOOL_NAME
    assert tag_value(inst["Tags"], "ManagedBy") == "aws-account-bootstrap"
    assert tag_value(inst["Tags"], "Name") == f"fms-trigger-{inst['VpcId']}"

    # Check the primary ENI (moto's instance-level SecurityGroups view is unreliable).
    sg_ids = [g["GroupId"] for g in inst["NetworkInterfaces"][0]["Groups"]]
    sgs = ec2.describe_security_groups(GroupIds=sg_ids)["SecurityGroups"]
    assert len(sgs) == 1
    sg = sgs[0]
    assert sg["GroupName"] == tool.DEFAULT_SG_NAME
    assert sg["IpPermissions"] == []
    assert sg["IpPermissionsEgress"] == []
    assert tag_value(sg["Tags"], "Name") == "fms-trigger-deny-all"


def test_create_is_idempotent(ec2, capsys):
    assert run("create") == 0
    assert run("create") == 0
    assert len(tool.find_tool_instances(ec2)) == 1
    assert len(tool.find_tool_sgs(ec2)) == 1


def test_create_specific_vpc_and_x86(ec2, capsys):
    vpc = ec2.create_vpc(CidrBlock="10.9.0.0/16")["Vpc"]["VpcId"]
    ec2.create_subnet(VpcId=vpc, CidrBlock="10.9.1.0/24", AvailabilityZone=f"{REGION}a")
    assert run("create", "--vpc-id", vpc, "--instance-type", "t3.nano") == 0
    (inst,) = tool.find_tool_instances(ec2, vpc)
    assert inst["InstanceType"] == "t3.nano"
    assert inst["VpcId"] == vpc


def test_refuses_foreign_sg_name(ec2):
    vpc = tool.resolve_vpc(ec2, None)
    ec2.create_security_group(GroupName=tool.DEFAULT_SG_NAME, Description="x", VpcId=vpc)
    assert tool.run_cli(lambda a: run("create")) == 2


def test_dry_run_creates_nothing(ec2):
    assert run("create", "--dry-run") == 0
    assert tool.find_tool_instances(ec2) == []
    assert tool.find_tool_sgs(ec2) == []


def test_destroy(ec2, capsys):
    run("create")
    assert run("status") == 0
    assert run("destroy", "--yes") == 0
    assert tool.find_tool_instances(ec2) == []
    assert tool.find_tool_sgs(ec2) == []
