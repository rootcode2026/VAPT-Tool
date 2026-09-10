# E1 — AWS Live Discovery

> Status: IMPLEMENTED (pending merge). DISCOVERY ONLY — no security checks,
> IAM analysis, CSPM scoring, attack paths, or remediation (E2–E9).

## Architecture

- Backend `app/services/aws_connector.py`: config validation + STS AssumeRole +
  account identity + region listing (fast ops for the connection-test endpoint).
- Worker `worker/app/aws_discovery.py`: full multi-service discovery engine
  (boto3 lazily imported; injectable client factory for tests).
- Worker `worker/app/cloud_discovery.py`: Celery task
  `app.tasks.cloud_discovery.discover_cloud` (fills the previously referenced
  but unimplemented task name). Loads/validates the connection, assumes the
  role, verifies identity, discovers regions + services, persists via existing
  `upsert_assets`/`upsert_relationships` (scan_id NULL — FKs are nullable),
  updates the run + connection, emits audit events.
- Reuses: CloudConnection model (+3 identifier columns), Asset/AssetRelationship
  + canonical types + existing relationship taxonomy, Celery/RabbitMQ/worker
  pools, AuditService, secret store (legacy path), RBAC, tenant isolation.
- GCP/Azure behavior untouched (mock adapters remain).

## Authentication model

- Cross-account IAM role assumption ONLY. Configured identifiers: 12-digit
  account ID, role ARN (`arn:aws:iam::<account>:role/<name>`), optional
  external ID, optional explicit region scope, name, enabled flag.
- The worker assumes the role with ambient credentials (instance profile /
  IRSA / environment — boto3 default chain). No static access keys anywhere:
  none accepted for role connections, none stored, none logged.
- Temporary credentials live in memory only (`creds.clear()` in `finally`),
  never persisted, never logged, never audited.
- Trust policy MUST constrain `sts:AssumeRole` to the platform principal and
  SHOULD require the configured ExternalId (confused-deputy protection).

## Required IAM permissions (read-only, discovery)

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "sts:GetCallerIdentity",
      "ec2:DescribeRegions", "ec2:DescribeInstances", "ec2:DescribeVpcs",
      "ec2:DescribeSubnets", "ec2:DescribeRouteTables",
      "ec2:DescribeSecurityGroups", "ec2:DescribeInternetGateways",
      "ec2:DescribeNatGateways", "ec2:DescribeNetworkInterfaces",
      "elasticloadbalancing:DescribeLoadBalancers",
      "rds:DescribeDBInstances",
      "lambda:ListFunctions", "lambda:GetFunction",
      "ecs:ListClusters", "ecs:DescribeClusters", "ecs:ListServices",
      "ecs:DescribeServices",
      "ecr:DescribeRepositories",
      "s3:ListAllMyBuckets", "s3:GetBucketLocation",
      "iam:ListRoles", "iam:ListUsers", "iam:ListGroups", "iam:GetRole",
      "iam:GetUser", "iam:GetGroup"
    ],
    "Resource": "*"
  }]
}
```

Grant least privilege per service as needed; missing permissions degrade to
bounded warnings (never false absence).

## Discovery scope (E1)

Account identity, regions, EC2 instances, VPCs, subnets, route tables,
security groups, internet/NAT gateways, network interfaces, S3 buckets, RDS
instances, ALB/NLB, ECS clusters + services, ECR repositories, Lambda
functions, IAM roles/users/groups (identity fields only).

## Regional behavior

Explicit connection region scope wins; otherwise EC2 DescribeRegions (never
hardcoded). Regional services run per region; S3/IAM run once globally
(bucket attributed to its location region). Per-region outcome recorded;
region failure never fails sibling regions.

## Partial discovery semantics

- All regions ok → `completed`; some failed → `partial` (with per-region
  results + warnings); all failed → `failed`.
- Permission denial → warning ("unavailable due to insufficient permissions"),
  no retry, never reported as absence.
- Throttling/transient → bounded retry (3 attempts, backoff, paginators capped).
- Partial runs never delete or degrade previously known assets (upsert merges,
  first_seen preserved).

## Asset normalization

- Types: existing `cloud_account` (`cloud_account:aws:{account}:global`) and
  `cloud_resource` (ARN when stable, else
  `cloud_resource:aws:{account}:{region}:{service}:{type}:{id}`).
- Metadata (bounded, sanitized): provider/service/resource_type/resource_id/
  arn/region/account_id/name/tags(≤20)/allowlisted service fields/sources/
  observed_at. Secrets, user data, and raw API responses never stored.
- Canonical values pass through existing normalization (lowercased) —
  deterministic and idempotent; E2 correlation must compare canonically.

## Relationship normalization

Existing taxonomy only (`contains`, `uses`) — no new types. Evidence-backed:
account contains all; VPC contains subnet/SG/RT/IGW/RDS/LB; subnet contains
EC2/ENI/NAT/Lambda-in-VPC; cluster contains service; EC2/RDS/Lambda/service/ENI
use SGs; subnet uses route table (same-VPC association). Nothing invented
without API evidence (e.g., no cluster edge without the cluster ARN).

## Security limitations

- Ambient worker credentials must be minimally scoped (instance profile/IRSA
  recommended; static env keys discouraged).
- KMS/Vault secret integration remains a documented platform stub; E1 stores
  no secrets so it does not depend on it.
- `container`/`sqlmap`-style exclusions do not apply here; workspace-scanner
  limitation is unrelated (no workspace used).
- Pre-existing `GET /api/v1/cloud/assets` serialization bug fixed as required
  by E1 (SQLAlchemy MetaData leaked into responses whenever cloud assets
  existed); regression test added.
- `alembic upgrade head` remains pre-existing-blocked at `o1p2q3r4s5t6`;
  E1 migration verified via offline SQL; live DDL applied out-of-band.

## E2/E3/E4/E5 dependencies

E2 (checks) needs: resource metadata above + check runner over persisted
assets. E3 (IAM) needs: IAM resources + policy documents (NOT collected in
E1 — `iam:GetPolicy*` deliberately excluded). E4 (network) needs: SG rules +
route details (E1 stores IDs/attachments; full rule bodies are E4 scope).
E5 (storage) needs: bucket policies/encryption state (E1 stores identity only).
