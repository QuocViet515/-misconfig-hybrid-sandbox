"""
Apply a generated IaC remediation bundle, push a branch, and open a GitHub PR.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def run_git(args: list[str], cwd: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        check=False,
        text=True,
        capture_output=True,
    )
    if check and result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result


def save_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def copy_fixed_tree(source_dir: Path, dest_dir: Path) -> None:
    for path in source_dir.rglob("*"):
        if path.is_dir():
            continue
        rel_path = path.relative_to(source_dir)
        target = dest_dir / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)


def create_pull_request(repo: str, token: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/pulls",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "misconfig-auto-remediate",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Open a GitHub PR from an IaC remediation bundle")
    parser.add_argument(
        "--bundle-dir",
        default="artifacts/iac_pr/checkov_pr_bundle",
        help="Directory containing summary.json, fixed_tree/, and PR_BODY.md",
    )
    parser.add_argument("--repo-root", default=".", help="Repository root")
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""))
    parser.add_argument("--base-branch", default="main")
    parser.add_argument("--head-branch", default="")
    parser.add_argument("--commit-message", default="Apply automated Terraform remediation bundle")
    parser.add_argument("--title-prefix", default="Auto-remediate Terraform misconfigurations")
    parser.add_argument("--allow-dirty", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    bundle_dir = Path(args.bundle_dir).resolve()
    repo_root = Path(args.repo_root).resolve()
    summary = json.loads((bundle_dir / "summary.json").read_text(encoding="utf-8"))
    pr_body = (bundle_dir / "PR_BODY.md").read_text(encoding="utf-8")
    fixed_tree = bundle_dir / "fixed_tree" / "iac" / "terraform"

    if int(summary.get("supported_findings_count", 0)) <= 0:
        logger.info("No supported findings in bundle; skipping PR creation")
        return 0

    if not args.allow_dirty:
        status = run_git(["status", "--porcelain"], repo_root)
        if status.stdout.strip():
            raise RuntimeError("Repository worktree must be clean before auto-opening a PR")

    branch_name = args.head_branch or summary.get("suggested_branch") or "autofix/generated-bundle"
    title = f"{args.title_prefix} ({summary.get('supported_findings_count', 0)} findings)"

    if args.dry_run:
        logger.info("Dry run only; branch %s and PR were not created", branch_name)
        save_json(
            bundle_dir / "github_pr_preview.json",
            {
                "branch": branch_name,
                "title": title,
                "base": args.base_branch,
                "files_changed": summary.get("files_changed", []),
            },
        )
        return 0

    copy_fixed_tree(fixed_tree, repo_root / "iac" / "terraform")

    diff_check = run_git(["status", "--porcelain", "--", "iac/terraform"], repo_root)
    if not diff_check.stdout.strip():
        logger.info("Bundle did not change repository files; skipping PR creation")
        return 0

    run_git(["checkout", "-b", branch_name], repo_root)
    run_git(["config", "user.name", "github-actions[bot]"], repo_root)
    run_git(["config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com"], repo_root)
    run_git(["add", "iac/terraform"], repo_root)
    run_git(["commit", "-m", args.commit_message], repo_root)
    run_git(["push", "origin", branch_name], repo_root)

    if not args.repo or not args.token:
        logger.info("Branch pushed, but repo/token missing so PR creation is skipped")
        save_json(bundle_dir / "github_pr_preview.json", {"branch": branch_name, "title": title})
        return 0

    payload = {
        "title": title,
        "head": branch_name,
        "base": args.base_branch,
        "body": pr_body,
        "maintainer_can_modify": True,
    }
    try:
        response = create_pull_request(args.repo, args.token, payload)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(exc.read().decode("utf-8", "ignore")) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(str(exc)) from exc

    save_json(bundle_dir / "github_pr_response.json", response)
    logger.info("Opened PR: %s", response.get("html_url"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
