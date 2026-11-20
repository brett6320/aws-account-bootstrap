# aws-account-bootstrap

Small, profile-aware tools (Python + boto3) for bootstrapping AWS accounts.

## Setup

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt          # requirements-dev.txt for tests
```

Every tool accepts `--profile/-p` and `--region/-r`. If omitted, the standard
boto3 credential chain is used (`AWS_PROFILE`, `AWS_REGION`, `~/.aws/config`, SSO, etc.).
SSO profiles work as-is — run `aws sso login --profile <name>` first.

## Tag configuration

Tags for every resource type live in [`config/tags.yaml`](config/tags.yaml):

```yaml
common:            # applied to everything
  ManagedBy: aws-account-bootstrap
resources:         # merged on top of common, per resource type
  instance:          { Name: "fms-trigger-${vpc_id}" }
  volume:            { Name: "fms-trigger-root-${vpc_id}" }
  network_interface: { Name: "fms-trigger-eni-${vpc_id}" }
  security_group:    { Name: fms-trigger-deny-all }
```

Placeholders `${account_id}`, `${region}`, `${profile}` and `${vpc_id}` are
substituted at runtime. Use `--tags-config path/to/other.yaml` to point at a
different file (e.g. one per org/OU). Tools also add a `bootstrap:tool` tag
that they use to find their own resources for `status`/`destroy`.

If your Firewall Manager policy scopes resources by tag, put those tags here.

## Tools

### `ec2_fms_trigger` — make Firewall Manager build its security groups

Firewall Manager security group policies only replicate their SGs into a VPC
once there's an in-scope resource there. This launches the smallest possible
instance to trigger that.

| Setting | Value |
|---|---|
| AMI | Latest Amazon Linux 2023, from the public SSM parameter `/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-<arch>` |
| Instance type | Cheapest offered in the AZ: `t4g.nano` → `t3a.nano` → `t3.nano` → `t2.nano` (override with `--instance-type`) |
| IAM | No instance profile, no key pair |
| Network | Default VPC unless `--vpc-id`/`--subnet-id`; no public IP |
| Security group | `fms-trigger-deny-all`: **no ingress and no egress rules** (the default allow-all egress rule is revoked) |
| Hardening | IMDSv2 required, encrypted gp3 root volume, `standard` CPU credits (no T-unlimited charges) |

```bash
# Launch in the default VPC
python -m bootstrap.ec2_fms_trigger create -p my-account -r us-east-1

# Launch in a specific VPC, wait until running
python -m bootstrap.ec2_fms_trigger create -p my-account --vpc-id vpc-0abc... --wait

# Check what would happen (EC2 DryRun, creates nothing)
python -m bootstrap.ec2_fms_trigger create -p my-account --dry-run

# Show what this tool created
python -m bootstrap.ec2_fms_trigger status -p my-account

# Clean up once Firewall Manager has created its SGs
python -m bootstrap.ec2_fms_trigger destroy -p my-account --vpc-id vpc-0abc... --yes
```

`create` is idempotent: if an instance from this tool already exists in the
VPC it does nothing (use `--force` to launch another). The security group is
reused if present, and any rules on it are stripped.

`destroy` only touches resources tagged `bootstrap:tool=ec2-fms-trigger`.
Security groups created by Firewall Manager are left alone. If FMS has
attached its own SG to the instance ENI, that's fine — the ENI is deleted with
the instance.

**IAM permissions needed:** `sts:GetCallerIdentity`, `ssm:GetParameter`,
`ec2:Describe*`, `ec2:RunInstances`, `ec2:CreateTags`,
`ec2:CreateSecurityGroup`, `ec2:RevokeSecurityGroupIngress`,
`ec2:RevokeSecurityGroupEgress`, `ec2:TerminateInstances`,
`ec2:DeleteSecurityGroup`.

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

Tests run against [moto](https://github.com/getmoto/moto); no AWS account needed.
