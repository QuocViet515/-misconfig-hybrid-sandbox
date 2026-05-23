"""
Execute AWS runtime remediation flows for the capstone scenarios.
"""
from __future__ import annotations

import argparse
import copy
import json
import logging
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from uuid import NAMESPACE_URL, uuid5

from ..models import RemediationEvent, RemediationStatus, StatusEnum
from ..siem.publisher import load_decisions, load_findings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[2]


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def stable_uuid(seed: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"aws-runtime:{seed}"))


def save_json(path: str | Path, payload: Any) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def compact_timestamp() -> str:
    return utc_now().strftime("%Y%m%d%H%M%S")


def make_db_identifier(base: str, suffix: str, max_length: int = 63) -> str:
    clean_base = "".join(char if char.isalnum() or char == "-" else "-" for char in base).strip("-").lower()
    reserved = len(suffix) + 1
    trimmed = clean_base[: max_length - reserved].rstrip("-")
    return f"{trimmed}-{suffix}"


def run_command(command: List[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=False,
        text=True,
        capture_output=True,
    )


def run_checked(command: List[str]) -> subprocess.CompletedProcess[str]:
    result = run_command(command)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"Command failed: {' '.join(command)}")
    return result


def run_aws_json(args: List[str]) -> Any:
    result = run_checked(["aws", *args, "--output", "json"])
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"aws {' '.join(args)} failed")
    return json.loads(result.stdout or "{}")


def aws_cli_available() -> bool:
    return shutil.which("aws") is not None


def custodian_available() -> bool:
    return shutil.which("custodian") is not None


def ansible_available() -> bool:
    return shutil.which("ansible-playbook") is not None


def scenario_file(finding: Dict[str, Any]) -> str:
    metadata = finding.get("metadata") or {}
    return Path(str(metadata.get("file_path") or "")).name


def classify_runtime_flow(finding: Dict[str, Any]) -> Optional[str]:
    if str(finding.get("provider") or "") != "aws":
        return None

    file_name = scenario_file(finding)
    if file_name == "m1_public_s3.tf":
        return "public_s3"
    if file_name == "m2_wide_open_sg.tf":
        return "open_security_group"
    if file_name == "m4_unencrypted_storage.tf":
        return "storage_encryption"

    text = " ".join(
        str(value or "")
        for value in (
            finding.get("title"),
            finding.get("description"),
            finding.get("resource_type"),
            finding.get("resource_id"),
        )
    ).lower()
    if "s3" in text and "public" in text:
        return "public_s3"
    if "security group" in text and ("0.0.0.0/0" in text or "ssh" in text or "rdp" in text):
        return "open_security_group"
    if "encryption" in text and any(token in text for token in ("s3", "ebs", "snapshot", "rds")):
        return "storage_encryption"
    return None


def approval_granted(
    decision: Dict[str, Any],
    finding_id: str,
    approved_ids: set[str],
    approve_all_manual: bool,
) -> bool:
    if decision.get("recommendation") == "auto_remediate":
        return True
    return approve_all_manual or finding_id in approved_ids


def update_finding_after_success(finding: Dict[str, Any], completed_at: datetime) -> Dict[str, Any]:
    updated = copy.deepcopy(finding)
    updated["status"] = StatusEnum.REMEDIATED.value
    updated["remediation_status"] = RemediationStatus.SUCCESS.value
    updated["remediated_at"] = completed_at.isoformat().replace("+00:00", "Z")
    updated["last_seen_at"] = updated["remediated_at"]
    return updated


def create_event(
    *,
    finding: Dict[str, Any],
    decision: Dict[str, Any],
    status: RemediationStatus,
    started_at: datetime,
    completed_at: Optional[datetime],
    manual_approval: bool,
    dry_run: bool,
    pipeline_source: str,
    branch: str,
    commit_sha: str,
    commands: List[List[str]],
    notes: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    duration = None
    if completed_at is not None:
        duration = round((completed_at - started_at).total_seconds(), 3)
    event = RemediationEvent(
        event_id=stable_uuid(
            f"{finding.get('finding_id')}:{json.dumps(commands, sort_keys=True)}:{json.dumps(metadata or {}, sort_keys=True, default=str)}"
        ),
        finding_id=str(finding.get("finding_id") or ""),
        finding_code=str(finding.get("finding_code") or ""),
        provider=str(finding.get("provider") or ""),
        resource_id=str(finding.get("resource_id") or ""),
        action_kind="runtime_remediation",
        recommendation=str(decision.get("recommendation") or "manual_review"),
        status=status,
        started_at=started_at,
        completed_at=completed_at,
        duration_seconds=duration,
        manual_approval=manual_approval,
        dry_run=dry_run,
        pipeline_source=pipeline_source,
        branch=branch,
        commit_sha=commit_sha,
        command=[" && ".join(" ".join(cmd) for cmd in commands)] if commands else None,
        notes=notes,
        metadata=metadata or {},
    )
    return event.model_dump(mode="json")


def list_bucket_names(prefix: str) -> List[str]:
    payload = run_aws_json(["s3api", "list-buckets", "--query", f"Buckets[?starts_with(Name, '{prefix}-')].Name"])
    return [name for name in payload if isinstance(name, str)]


def bucket_has_scenario(bucket_name: str, scenarios: set[str]) -> bool:
    result = run_command(["aws", "s3api", "get-bucket-tagging", "--bucket", bucket_name, "--output", "json"])
    if result.returncode != 0:
        return False
    payload = json.loads(result.stdout or "{}")
    for tag in payload.get("TagSet", []):
        if tag.get("Key") == "Scenario" and tag.get("Value") in scenarios:
            return True
    return False


def discover_buckets(prefix: str, scenarios: set[str], explicit_name: str = "") -> List[str]:
    if explicit_name and not explicit_name.startswith("aws_") and "/" not in explicit_name:
        return [explicit_name]
    names: List[str] = []
    for bucket_name in list_bucket_names(prefix):
        if bucket_has_scenario(bucket_name, scenarios):
            names.append(bucket_name)
    return names


def discover_security_groups(region: str, explicit_id: str = "") -> List[str]:
    if explicit_id.startswith("sg-"):
        return [explicit_id]
    payload = run_aws_json(
        [
            "ec2",
            "describe-security-groups",
            "--region",
            region,
            "--filters",
            "Name=tag:Scenario,Values=M2-WideOpenSG",
            "--query",
            "SecurityGroups[].GroupId",
        ]
    )
    return [sg_id for sg_id in payload if isinstance(sg_id, str)]


def discover_storage_targets(prefix: str, region: str) -> Dict[str, List[Dict[str, Any]]]:
    buckets = discover_buckets(prefix, {"M4-UnencryptedStorage"})
    volumes = run_aws_json(
        [
            "ec2",
            "describe-volumes",
            "--region",
            region,
            "--filters",
            "Name=tag:Scenario,Values=M4-UnencryptedStorage",
            "--query",
            "Volumes[].{VolumeId:VolumeId,Encrypted:Encrypted,AvailabilityZone:AvailabilityZone,State:State,Attachments:Attachments,Tags:Tags,Size:Size,VolumeType:VolumeType}",
        ]
    )
    snapshots = run_aws_json(
        [
            "ec2",
            "describe-snapshots",
            "--region",
            region,
            "--owner-ids",
            "self",
            "--filters",
            "Name=tag:Scenario,Values=M4-UnencryptedStorage",
            "--query",
            "Snapshots[].{SnapshotId:SnapshotId,Encrypted:Encrypted,VolumeId:VolumeId,Tags:Tags,Description:Description}",
        ]
    )
    db_payload = run_aws_json(
        [
            "rds",
            "describe-db-instances",
            "--region",
            region,
        ]
    )
    db_instances = [
        {
            "DBInstanceIdentifier": item.get("DBInstanceIdentifier"),
            "StorageEncrypted": item.get("StorageEncrypted"),
            "DBSubnetGroupName": ((item.get("DBSubnetGroup") or {}).get("DBSubnetGroupName")),
            "VpcSecurityGroupIds": [
                sg.get("VpcSecurityGroupId")
                for sg in item.get("VpcSecurityGroups", [])
                if sg.get("VpcSecurityGroupId")
            ],
            "DBInstanceClass": item.get("DBInstanceClass"),
            "DBInstanceStatus": item.get("DBInstanceStatus"),
            "DeletionProtection": item.get("DeletionProtection"),
            "MultiAZ": item.get("MultiAZ"),
            "Engine": item.get("Engine"),
            "ReadReplicaDBInstanceIdentifiers": item.get("ReadReplicaDBInstanceIdentifiers", []),
        }
        for item in (db_payload.get("DBInstances", []) if isinstance(db_payload, dict) else [])
        if str(item.get("DBInstanceIdentifier") or "").startswith(f"{prefix}-m4-")
    ]
    return {
        "buckets": [{"Name": name} for name in buckets],
        "volumes": volumes or [],
        "snapshots": snapshots or [],
        "db_instances": db_instances or [],
    }


def build_public_s3_policy(bucket_names: List[str], region: str, finding_id: str) -> Tuple[Path, str]:
    policy_name = f"close-public-s3-{finding_id[:8]}"
    policy_dir = REPO_ROOT / "artifacts" / "remediation" / "custodian"
    policy_dir.mkdir(parents=True, exist_ok=True)
    policy_path = policy_dir / f"{policy_name}.yml"
    if len(bucket_names) == 1:
        filter_block = [
            "      - type: value",
            "        key: Name",
            f"        value: {bucket_names[0]}",
        ]
    else:
        filter_block = ["      - or:"]
        for bucket_name in bucket_names:
            filter_block.extend(
                [
                    "        - type: value",
                    "          key: Name",
                    f"          value: {bucket_name}",
                ]
            )
    policy_text = "\n".join(
        [
            "policies:",
            f"  - name: {policy_name}",
            "    resource: aws.s3",
            f"    region: {region}",
            "    filters:",
            *filter_block,
            "    actions:",
            "      - type: delete-global-grants",
            "      - type: set-public-block",
            "",
        ]
    )
    policy_path.write_text(policy_text, encoding="utf-8")
    return policy_path, policy_name


def execute_public_s3_flow(
    finding: Dict[str, Any],
    *,
    region: str,
    project_prefix: str,
    execute: bool,
    simulate_success: bool,
    known_buckets: Optional[List[str]] = None,
) -> Tuple[RemediationStatus, str, List[List[str]], Dict[str, Any]]:
    buckets = known_buckets
    if buckets is None:
        buckets = discover_buckets(
            project_prefix,
            {"M1-PublicS3", "M1-PublicS3Policy"},
            explicit_name=str(finding.get("resource_id") or ""),
        )
    if not buckets:
        return RemediationStatus.PENDING, "No deployed S3 buckets matched the public-access scenario.", [], {}

    policy_path, _ = build_public_s3_policy(buckets, region, str(finding.get("finding_id") or "finding"))
    output_dir = policy_path.parent / policy_path.stem
    command = ["custodian", "run", "-s", str(output_dir), str(policy_path)]
    metadata = {
        "policy_file": str(policy_path),
        "output_dir": str(output_dir),
        "bucket_names": buckets,
    }

    if simulate_success:
        return RemediationStatus.SUCCESS, "Simulated Cloud Custodian remediation for public S3 access.", [command], metadata
    if not execute:
        return RemediationStatus.PENDING, "Dry-run only. Cloud Custodian policy generated but not executed.", [command], metadata
    if not custodian_available():
        return RemediationStatus.FAILED, "custodian binary is not available on this machine.", [command], metadata

    result = run_command(command)
    metadata["stdout"] = result.stdout
    metadata["stderr"] = result.stderr
    if result.returncode != 0:
        return RemediationStatus.FAILED, result.stderr.strip() or "Cloud Custodian execution failed.", [command], metadata
    return RemediationStatus.SUCCESS, "Cloud Custodian closed public S3 access.", [command], metadata


def execute_open_sg_flow(
    finding: Dict[str, Any],
    *,
    region: str,
    execute: bool,
    simulate_success: bool,
    known_sg_ids: Optional[List[str]] = None,
) -> Tuple[RemediationStatus, str, List[List[str]], Dict[str, Any]]:
    sg_ids = known_sg_ids
    if sg_ids is None:
        sg_ids = discover_security_groups(region, explicit_id=str(finding.get("resource_id") or ""))
    if not sg_ids:
        return RemediationStatus.PENDING, "No deployed security groups matched the wide-open scenario.", [], {}

    playbook = REPO_ROOT / "ansible" / "remediate_open_sg.yml"
    commands: List[List[str]] = []
    log_files: List[str] = []
    for sg_id in sg_ids:
        log_path = REPO_ROOT / "artifacts" / "remediation" / "ansible" / f"{sg_id}.json"
        commands.append(
            [
                "ansible-playbook",
                "-i",
                "localhost,",
                "-c",
                "local",
                str(playbook),
                "-e",
                f"aws_region={region}",
                "-e",
                f"sg_id={sg_id}",
                "-e",
                f"log_file={log_path}",
            ]
        )
        log_files.append(str(log_path))

    metadata = {"security_group_ids": sg_ids, "playbook": str(playbook), "log_files": log_files}
    if simulate_success:
        return RemediationStatus.SUCCESS, "Simulated Ansible remediation for wide-open security group rules.", commands, metadata
    if not execute:
        return RemediationStatus.PENDING, "Dry-run only. Ansible playbook prepared but not executed.", commands, metadata
    if not ansible_available():
        return RemediationStatus.FAILED, "ansible-playbook is not available on this machine.", commands, metadata

    metadata["command_results"] = []
    for command in commands:
        result = run_command(command)
        metadata["command_results"].append(
            {"command": command, "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
        )
        if result.returncode != 0:
            return RemediationStatus.FAILED, result.stderr.strip() or "Ansible playbook execution failed.", commands, metadata
    return RemediationStatus.SUCCESS, "Ansible removed dangerous security group rules.", commands, metadata


def encrypt_bucket_objects(region: str, bucket_name: str) -> Dict[str, Any]:
    metadata: Dict[str, Any] = {"bucket": bucket_name, "re_encrypted_objects": []}
    run_checked(
        [
            "aws",
            "s3api",
            "put-bucket-encryption",
            "--region",
            region,
            "--bucket",
            bucket_name,
            "--server-side-encryption-configuration",
            json.dumps(
                {
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "AES256",
                            }
                        }
                    ]
                }
            ),
        ]
    )
    objects = run_aws_json(
        [
            "s3api",
            "list-objects-v2",
            "--bucket",
            bucket_name,
            "--query",
            "Contents[].Key",
        ]
    )
    for key in objects or []:
        head = run_aws_json(["s3api", "head-object", "--bucket", bucket_name, "--key", key])
        if head.get("ServerSideEncryption"):
            continue
        result = run_command(
            [
                "aws",
                "s3api",
                "copy-object",
                "--region",
                region,
                "--bucket",
                bucket_name,
                "--key",
                key,
                "--copy-source",
                f"{bucket_name}/{key}",
                "--metadata-directive",
                "COPY",
                "--server-side-encryption",
                "AES256",
            ]
        )
        metadata["re_encrypted_objects"].append({"key": key, "returncode": result.returncode})
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or f"Failed to encrypt object {key}")
    return metadata


def maybe_extract_tag(tags: Iterable[Dict[str, Any]], key: str) -> str:
    for tag in tags:
        if tag.get("Key") == key:
            return str(tag.get("Value") or "")
    return ""


def copy_unencrypted_snapshot(region: str, snapshot_id: str, description: str) -> str:
    target_id = f"{snapshot_id}-enc"
    copy_result = run_aws_json(
        [
            "ec2",
            "copy-snapshot",
            "--region",
            region,
            "--source-region",
            region,
            "--source-snapshot-id",
            snapshot_id,
            "--encrypted",
            "--description",
            description,
            "--query",
            "SnapshotId",
        ]
    )
    encrypted_snapshot_id = str(copy_result)
    run_checked(["aws", "ec2", "wait", "snapshot-completed", "--region", region, "--snapshot-ids", encrypted_snapshot_id])
    return encrypted_snapshot_id


def remediate_unencrypted_volumes(region: str, volumes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for volume in volumes:
        volume_id = str(volume.get("VolumeId") or "")
        if not volume_id or volume.get("Encrypted") is True:
            continue
        attachments = volume.get("Attachments") or []
        if attachments:
            results.append(
                {
                    "volume_id": volume_id,
                    "status": "manual",
                    "reason": "Volume is attached; replacement requires coordinated cutover.",
                }
            )
            continue
        snapshot_result = run_aws_json(
            [
                "ec2",
                "create-snapshot",
                "--region",
                region,
                "--volume-id",
                volume_id,
                "--description",
                f"Remediation snapshot for {volume_id}",
                "--query",
                "SnapshotId",
            ]
        )
        snapshot_id = str(snapshot_result)
        run_checked(["aws", "ec2", "wait", "snapshot-completed", "--region", region, "--snapshot-ids", snapshot_id])
        encrypted_snapshot_id = copy_unencrypted_snapshot(region, snapshot_id, f"Encrypted copy for {volume_id}")
        create_result = run_aws_json(
            [
                "ec2",
                "create-volume",
                "--region",
                region,
                "--availability-zone",
                str(volume.get("AvailabilityZone") or ""),
                "--snapshot-id",
                encrypted_snapshot_id,
                "--volume-type",
                str(volume.get("VolumeType") or "gp3"),
                "--tag-specifications",
                json.dumps(
                    [
                        {
                            "ResourceType": "volume",
                            "Tags": [
                                {"Key": "Name", "Value": maybe_extract_tag(volume.get("Tags") or [], "Name")},
                                {"Key": "Scenario", "Value": "M4-UnencryptedStorage"},
                                {"Key": "RemediatedFrom", "Value": volume_id},
                            ],
                        }
                    ]
                ),
                "--query",
                "VolumeId",
            ]
        )
        encrypted_volume_id = str(create_result)
        run_checked(["aws", "ec2", "wait", "volume-available", "--region", region, "--volume-ids", encrypted_volume_id])
        run_checked(["aws", "ec2", "delete-volume", "--region", region, "--volume-id", volume_id])
        run_checked(["aws", "ec2", "delete-snapshot", "--region", region, "--snapshot-id", snapshot_id])
        results.append(
            {
                "volume_id": volume_id,
                "replacement_volume_id": encrypted_volume_id,
                "encrypted_snapshot_id": encrypted_snapshot_id,
                "status": "success",
            }
        )
    return results


def remediate_unencrypted_snapshots(region: str, snapshots: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for snapshot in snapshots:
        snapshot_id = str(snapshot.get("SnapshotId") or "")
        if not snapshot_id or snapshot.get("Encrypted") is True:
            continue
        encrypted_snapshot_id = copy_unencrypted_snapshot(region, snapshot_id, f"Encrypted copy for {snapshot_id}")
        run_checked(["aws", "ec2", "delete-snapshot", "--region", region, "--snapshot-id", snapshot_id])
        results.append(
            {
                "snapshot_id": snapshot_id,
                "replacement_snapshot_id": encrypted_snapshot_id,
                "status": "success",
            }
        )
    return results


def wait_for_rds_instance(region: str, identifier: str) -> None:
    run_checked(["aws", "rds", "wait", "db-instance-available", "--region", region, "--db-instance-identifier", identifier])


def rename_rds_instance(region: str, current_identifier: str, new_identifier: str) -> None:
    run_checked(
        [
            "aws",
            "rds",
            "modify-db-instance",
            "--region",
            region,
            "--db-instance-identifier",
            current_identifier,
            "--new-db-instance-identifier",
            new_identifier,
            "--apply-immediately",
        ]
    )
    wait_for_rds_instance(region, new_identifier)


def remediate_unencrypted_rds(
    region: str,
    db_instances: List[Dict[str, Any]],
    *,
    force_cutover: bool = False,
    delete_archived_instance: bool = False,
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for db in db_instances:
        identifier = str(db.get("DBInstanceIdentifier") or "")
        if not identifier or db.get("StorageEncrypted") is True:
            continue
        if db.get("ReadReplicaDBInstanceIdentifiers"):
            results.append(
                {
                    "source_db_instance": identifier,
                    "status": "manual",
                    "reason": "DB instance has read replicas; coordinated cutover is still required.",
                }
            )
            continue

        suffix = compact_timestamp()
        snapshot_id = make_db_identifier(f"{identifier}-enc-source", suffix)
        encrypted_snapshot_id = make_db_identifier(f"{identifier}-enc-copy", suffix)
        archived_identifier = make_db_identifier(f"{identifier}-preenc", suffix)
        replacement_identifier = identifier if force_cutover else make_db_identifier(f"{identifier}-encrypted", suffix)
        run_checked(["aws", "rds", "create-db-snapshot", "--region", region, "--db-instance-identifier", identifier, "--db-snapshot-identifier", snapshot_id])
        run_checked(["aws", "rds", "wait", "db-snapshot-available", "--region", region, "--db-snapshot-identifier", snapshot_id])
        run_checked(
            [
                "aws",
                "rds",
                "copy-db-snapshot",
                "--region",
                region,
                "--source-db-snapshot-identifier",
                snapshot_id,
                "--target-db-snapshot-identifier",
                encrypted_snapshot_id,
                "--kms-key-id",
                "alias/aws/rds",
                "--copy-tags",
            ]
        )
        run_checked(
            [
                "aws",
                "rds",
                "wait",
                "db-snapshot-available",
                "--region",
                region,
                "--db-snapshot-identifier",
                encrypted_snapshot_id,
            ]
        )
        if force_cutover:
            rename_rds_instance(region, identifier, archived_identifier)

        restore_command = [
            "aws",
            "rds",
            "restore-db-instance-from-db-snapshot",
            "--region",
            region,
            "--db-instance-identifier",
            replacement_identifier,
            "--db-snapshot-identifier",
            encrypted_snapshot_id,
        ]
        if db.get("DBInstanceClass"):
            restore_command.extend(["--db-instance-class", str(db.get("DBInstanceClass"))])
        if db.get("DBSubnetGroupName"):
            restore_command.extend(["--db-subnet-group-name", str(db.get("DBSubnetGroupName"))])
        security_groups = db.get("VpcSecurityGroupIds") or []
        if security_groups:
            restore_command.extend(["--vpc-security-group-ids", *security_groups])
        if db.get("MultiAZ") is True:
            restore_command.append("--multi-az")
        run_checked(restore_command)
        wait_for_rds_instance(region, replacement_identifier)

        payload: Dict[str, Any] = {
            "source_db_instance": identifier,
            "encrypted_snapshot_id": encrypted_snapshot_id,
            "replacement_db_instance": replacement_identifier,
        }
        if force_cutover:
            payload.update(
                {
                    "archived_db_instance": archived_identifier,
                    "status": "success-cutover",
                }
            )
            if delete_archived_instance:
                if db.get("DeletionProtection") is True:
                    run_checked(
                        [
                            "aws",
                            "rds",
                            "modify-db-instance",
                            "--region",
                            region,
                            "--db-instance-identifier",
                            archived_identifier,
                            "--no-deletion-protection",
                            "--apply-immediately",
                        ]
                    )
                    wait_for_rds_instance(region, archived_identifier)
                run_checked(
                    [
                        "aws",
                        "rds",
                        "delete-db-instance",
                        "--region",
                        region,
                        "--db-instance-identifier",
                        archived_identifier,
                        "--skip-final-snapshot",
                        "--delete-automated-backups",
                    ]
                )
                payload["archived_db_deleted"] = True
        else:
            payload["status"] = "pending-cutover"
        results.append(payload)
    return results


def execute_storage_flow(
    finding: Dict[str, Any],
    *,
    region: str,
    project_prefix: str,
    execute: bool,
    simulate_success: bool,
    force_rds_cutover: bool,
    delete_archived_rds: bool,
    known_targets: Optional[Dict[str, List[Dict[str, Any]]]] = None,
) -> Tuple[RemediationStatus, str, List[List[str]], Dict[str, Any]]:
    targets = known_targets
    if targets is None:
        targets = discover_storage_targets(project_prefix, region)
    commands: List[List[str]] = []
    for bucket in targets["buckets"]:
        commands.append(["aws", "s3api", "put-bucket-encryption", "--region", region, "--bucket", bucket["Name"], "--server-side-encryption-configuration", "<AES256-config>"])
    for volume in targets["volumes"]:
        commands.append(["aws", "ec2", "create-snapshot", "--region", region, "--volume-id", str(volume.get("VolumeId") or "")])
    for snapshot in targets["snapshots"]:
        commands.append(["aws", "ec2", "copy-snapshot", "--region", region, "--source-region", region, "--source-snapshot-id", str(snapshot.get("SnapshotId") or ""), "--encrypted"])
    for db in targets["db_instances"]:
        commands.append(["aws", "rds", "create-db-snapshot", "--region", region, "--db-instance-identifier", str(db.get("DBInstanceIdentifier") or "")])
        if force_rds_cutover:
            commands.append(
                [
                    "aws",
                    "rds",
                    "modify-db-instance",
                    "--region",
                    region,
                    "--db-instance-identifier",
                    str(db.get("DBInstanceIdentifier") or ""),
                    "--new-db-instance-identifier",
                    "<archived-id>",
                    "--apply-immediately",
                ]
            )
            commands.append(
                [
                    "aws",
                    "rds",
                    "restore-db-instance-from-db-snapshot",
                    "--region",
                    region,
                    "--db-instance-identifier",
                    str(db.get("DBInstanceIdentifier") or ""),
                    "--db-snapshot-identifier",
                    "<encrypted-snapshot>",
                ]
            )

    metadata: Dict[str, Any] = {"targets": targets}
    if not any(targets.values()):
        return RemediationStatus.PENDING, "No deployed storage resources matched the encryption scenario.", commands, metadata
    if simulate_success:
        return RemediationStatus.SUCCESS, "Simulated API remediation for encryption-at-rest.", commands, metadata
    if not execute:
        return RemediationStatus.PENDING, "Dry-run only. API remediation plan prepared but not executed.", commands, metadata
    if not aws_cli_available():
        return RemediationStatus.FAILED, "aws CLI is not available on this machine.", commands, metadata

    try:
        metadata["bucket_results"] = [encrypt_bucket_objects(region, bucket["Name"]) for bucket in targets["buckets"]]
        metadata["volume_results"] = remediate_unencrypted_volumes(region, targets["volumes"])
        metadata["snapshot_results"] = remediate_unencrypted_snapshots(region, targets["snapshots"])
        metadata["rds_results"] = remediate_unencrypted_rds(
            region,
            targets["db_instances"],
            force_cutover=force_rds_cutover,
            delete_archived_instance=delete_archived_rds,
        )
    except RuntimeError as exc:
        return RemediationStatus.FAILED, str(exc), commands, metadata

    pending_rds = [
        item for item in metadata.get("rds_results", [])
        if item.get("status") in {"pending-cutover", "manual"}
    ]
    if pending_rds:
        pending_cutover = [item for item in pending_rds if item.get("status") == "pending-cutover"]
        manual_items = [item for item in pending_rds if item.get("status") == "manual"]
        notes: List[str] = []
        if pending_cutover:
            notes.append("Encrypted replacement DB instances were created, but cutover is still pending.")
        if manual_items:
            notes.append("Some RDS targets still require manual handling, such as instances with read replicas.")
        return RemediationStatus.PENDING, " ".join(notes), commands, metadata
    return RemediationStatus.SUCCESS, "Encryption-at-rest remediation completed through AWS APIs.", commands, metadata


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Execute AWS runtime remediation flows")
    parser.add_argument("--findings", required=True, help="Findings JSON path")
    parser.add_argument("--decisions", required=True, help="Triage decisions JSON path")
    parser.add_argument("--region", default="ap-southeast-1")
    parser.add_argument("--project-prefix", default="threat-demo")
    parser.add_argument(
        "--output-events",
        default="artifacts/remediation/aws_runtime_events.json",
        help="Where to write remediation events",
    )
    parser.add_argument(
        "--output-findings-after",
        default="artifacts/remediation/aws_findings_after_runtime.json",
        help="Where to write findings after successful remediations",
    )
    parser.add_argument("--approve-finding-id", action="append", default=[])
    parser.add_argument("--approve-all-manual", action="store_true")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--simulate-success", action="store_true")
    parser.add_argument("--force-rds-cutover", action="store_true", help="Rename the original RDS instance and restore the encrypted replacement back to the original DB identifier")
    parser.add_argument("--delete-archived-rds", action="store_true", help="Delete the archived pre-cutover RDS instance after a forced cutover")
    parser.add_argument("--pipeline-source", default="aws-runtime-remediation")
    parser.add_argument("--branch", default="")
    parser.add_argument("--commit-sha", default="")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    findings = load_findings(args.findings)
    decisions = load_decisions(args.decisions)
    decision_lookup = {str(item.get("finding_id") or ""): item for item in decisions}
    approved_ids = {item for item in args.approve_finding_id if item}

    events: List[Dict[str, Any]] = []
    findings_after = copy.deepcopy(findings)
    by_id = {str(item.get("finding_id") or ""): item for item in findings_after}
    discovery_cache: Dict[str, Any] = {}
    flow_result_cache: Dict[str, Tuple[RemediationStatus, str, List[List[str]], Dict[str, Any]]] = {}

    for finding in findings:
        flow = classify_runtime_flow(finding)
        if flow is None:
            continue
        if not finding.get("remediation_available", True):
            continue

        finding_id = str(finding.get("finding_id") or "")
        decision = decision_lookup.get(
            finding_id,
            {"finding_id": finding_id, "recommendation": "manual_review"},
        )
        recommendation = str(decision.get("recommendation") or "manual_review")
        if recommendation == "ignore":
            continue

        started_at = utc_now()
        manual_approval = recommendation != "auto_remediate"
        if manual_approval and not approval_granted(decision, finding_id, approved_ids, args.approve_all_manual):
            events.append(
                create_event(
                    finding=finding,
                    decision=decision,
                    status=RemediationStatus.PENDING,
                    started_at=started_at,
                    completed_at=None,
                    manual_approval=False,
                    dry_run=not args.execute,
                    pipeline_source=args.pipeline_source,
                    branch=args.branch,
                    commit_sha=args.commit_sha,
                    commands=[],
                    notes="Manual approval required before AWS runtime remediation.",
                    metadata={"approval_required": True, "flow": flow},
                )
            )
            continue

        if flow in flow_result_cache:
            status, notes, commands, metadata = copy.deepcopy(flow_result_cache[flow])
        else:
            if flow == "public_s3":
                if flow not in discovery_cache:
                    discovery_cache[flow] = discover_buckets(
                        args.project_prefix,
                        {"M1-PublicS3", "M1-PublicS3Policy"},
                    )
                status, notes, commands, metadata = execute_public_s3_flow(
                    finding,
                    region=args.region,
                    project_prefix=args.project_prefix,
                    execute=args.execute,
                    simulate_success=args.simulate_success,
                    known_buckets=discovery_cache[flow],
                )
            elif flow == "open_security_group":
                if flow not in discovery_cache:
                    discovery_cache[flow] = discover_security_groups(args.region)
                status, notes, commands, metadata = execute_open_sg_flow(
                    finding,
                    region=args.region,
                    execute=args.execute,
                    simulate_success=args.simulate_success,
                    known_sg_ids=discovery_cache[flow],
                )
            else:
                if flow not in discovery_cache:
                    discovery_cache[flow] = discover_storage_targets(args.project_prefix, args.region)
                status, notes, commands, metadata = execute_storage_flow(
                    finding,
                    region=args.region,
                    project_prefix=args.project_prefix,
                    execute=args.execute,
                    simulate_success=args.simulate_success,
                    force_rds_cutover=args.force_rds_cutover,
                    delete_archived_rds=args.delete_archived_rds,
                    known_targets=discovery_cache[flow],
                )
            flow_result_cache[flow] = copy.deepcopy((status, notes, commands, metadata))

        completed_at = utc_now() if status != RemediationStatus.PENDING else None
        events.append(
            create_event(
                finding=finding,
                decision=decision,
                status=status,
                started_at=started_at,
                completed_at=completed_at,
                manual_approval=manual_approval,
                dry_run=not args.execute,
                pipeline_source=args.pipeline_source,
                branch=args.branch,
                commit_sha=args.commit_sha,
                commands=commands,
                notes=notes,
                metadata={"flow": flow, **(metadata or {})},
            )
        )
        if status == RemediationStatus.SUCCESS and completed_at is not None and finding_id in by_id:
            by_id[finding_id] = update_finding_after_success(by_id[finding_id], completed_at)

    save_json(args.output_events, events)
    save_json(args.output_findings_after, list(by_id.values()))
    logger.info("Wrote %s remediation events to %s", len(events), args.output_events)
    logger.info("Wrote post-remediation findings snapshot to %s", args.output_findings_after)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
