"""PostgreSQL-backed worker that fetches application commits temporarily and runs Trivy."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path

import psycopg

from vuln_intel import config, inventory_integration, repository_connections, scan_store
from vuln_intel.scan_matching import merge_components, parse_cyclonedx, parse_trivy_report
from vuln_intel.scan_service import combine_findings

log = logging.getLogger(__name__)
MAX_JSON_SIZE = 250 * 1024 * 1024


def _git_environment(temporary_dir: Path, repository_url: str, username: str, password: str):
    env = os.environ.copy()
    env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1"})
    global_config = temporary_dir / "gitconfig"
    global_config.write_text("", encoding="utf-8")
    env["GIT_CONFIG_GLOBAL"] = str(global_config)
    if password:
        askpass = temporary_dir / ("git-askpass.cmd" if os.name == "nt" else "git-askpass")
        if os.name == "nt":
            helper = temporary_dir / "git-askpass.py"
            helper.write_text(
                "import os, sys\n"
                "prompt = sys.argv[1].lower() if len(sys.argv) > 1 else ''\n"
                "key = 'VULN_GIT_USERNAME' if 'username' in prompt else 'VULN_GIT_PASSWORD'\n"
                "sys.stdout.write(os.environ.get(key, ''))\n",
                encoding="utf-8",
            )
            askpass.write_text(
                '@echo off\r\n'
                'python "%~dp0git-askpass.py" "%~1"\r\n',
                encoding="utf-8",
            )
        else:
            askpass.write_text(
                "#!/bin/sh\n"
                'case "$1" in *[Uu]sername*) printf "%s\\n" "$VULN_GIT_USERNAME" ;; '
                '*) printf "%s\\n" "$VULN_GIT_PASSWORD" ;; esac\n',
                encoding="utf-8",
            )
            askpass.chmod(0o700)
        env["GIT_ASKPASS"] = str(askpass)
        env["VULN_GIT_PASSWORD"] = password
        env["VULN_GIT_USERNAME"] = username
    return env


def checkout_commit(repository_url: str, commit_sha: str, destination: Path, temporary_dir: Path,
                    username: str = "", password: str = ""):
    clean_url = repository_connections.validate_repository_url(repository_url)
    env = _git_environment(temporary_dir, clean_url, username, password)
    destination.mkdir(parents=True, exist_ok=True)
    commands = [
        ["git", "init", "--quiet", str(destination)],
        ["git", "-C", str(destination), "remote", "add", "origin", clean_url],
        ["git", "-C", str(destination), "fetch", "--depth=1", "--no-tags", "origin", commit_sha],
        ["git", "-C", str(destination), "checkout", "--quiet", "--detach", "FETCH_HEAD"],
    ]
    for command in commands:
        result = subprocess.run(command, capture_output=True, text=True, timeout=600, env=env, check=False)
        if result.returncode:
            detail = (result.stderr or result.stdout or "git returned a non-zero exit status").strip()
            for secret in (username, password):
                if secret:
                    detail = detail.replace(secret, "[redacted]")
            raise RuntimeError(f"Repository checkout failed: {detail[:500]}")


def resolve_repository_head(repository_url: str, temporary_dir: Path, username: str = "", password: str = ""):
    clean_url = repository_connections.validate_repository_url(repository_url)
    env = _git_environment(temporary_dir, clean_url, username, password)
    result = subprocess.run(
        ["git", "ls-remote", "--symref", clean_url, "HEAD"],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
        check=False,
    )
    if result.returncode:
        detail = (result.stderr or result.stdout or "git returned a non-zero exit status").strip()
        for secret in (username, password):
            if secret:
                detail = detail.replace(secret, "[redacted]")
        raise RuntimeError(f"Could not resolve repository default branch: {detail[:500]}")
    commit_sha = ""
    ref = ""
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[0] == "ref:" and fields[2] == "HEAD":
            ref = fields[1]
        elif len(fields) == 2 and fields[1] == "HEAD" and re.fullmatch(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", fields[0]):
            commit_sha = fields[0].lower()
    if not commit_sha:
        raise RuntimeError("The repository did not report a valid default-branch commit.")
    if not ref:
        ref = "HEAD"
    return commit_sha, ref


def _run_trivy(repository: Path, output_dir: Path):
    cache_dir = Path(os.getenv("VULN_TRIVY_CACHE_DIR", str(config.DATA_DIR / "trivy-cache")))
    cache_dir.mkdir(parents=True, exist_ok=True)
    version_result = subprocess.run(
        [config.TRIVY_BINARY, "--version"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if version_result.returncode:
        raise RuntimeError("Could not read the Trivy version.")
    version_output = f"{version_result.stdout}\n{version_result.stderr}"
    version_match = re.search(r"(?m)^Version:\s*(\S+)", version_output)
    scanner_version = version_match.group(1) if version_match else ""
    if scanner_version != config.TRIVY_VERSION:
        raise RuntimeError(
            f"Trivy version mismatch: configured {config.TRIVY_VERSION}, found {scanner_version or 'unknown'}."
        )
    db_match = re.search(r"(?m)^\s*UpdatedAt:\s*(.+)$", version_output)
    scanner_db_updated = db_match.group(1).strip() if db_match else None
    report_path = output_dir / "report.json"
    sbom_path = output_dir / "sbom.cdx.json"
    common = [
        config.TRIVY_BINARY, "repo", "--scanners", "vuln",
        "--cache-dir", str(cache_dir), "--no-progress",
    ]
    for output_format, output_path in (("json", report_path), ("cyclonedx", sbom_path)):
        command = [*common, "--format", output_format, "--output", str(output_path), str(repository)]
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=config.TRIVY_TIMEOUT_SECONDS,
            check=False,
        )
        if result.returncode:
            detail = (result.stderr or result.stdout or "Trivy returned a non-zero exit status").strip()
            raise RuntimeError(f"Trivy {output_format} scan failed: {detail[:1000]}")
        if not output_path.is_file() or output_path.stat().st_size > MAX_JSON_SIZE:
            raise RuntimeError(f"Trivy {output_format} output is missing or exceeds the size limit.")
    return scanner_version, scanner_db_updated, report_path, sbom_path


def _read_json(path: Path):
    if path.stat().st_size > MAX_JSON_SIZE:
        raise RuntimeError("Trivy output exceeds the JSON size limit.")
    try:
        with path.open("r", encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not parse Trivy output {path.name}.") from exc


def _sha256(path: Path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def process_scan(run: dict):
    application = repository_connections.get_repository_connection(run["application_id"])
    credentials = repository_connections.get_provider_credentials(application["repository_url"])
    commit_sha = run["commit_sha"]
    ref = run["ref"]
    output_dir = config.SCAN_ARTIFACTS_DIR / run["run_id"]
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="vuln-scan-") as temp_name:
        temporary_dir = Path(temp_name)
        repository = temporary_dir / "repository"
        if commit_sha == "HEAD":
            commit_sha, ref = resolve_repository_head(
                application["repository_url"], temporary_dir,
                credentials["username"], credentials["password"],
            )
            scan_store.update_scan_target(run["run_id"], run["lease_token"], commit_sha, ref)
        checkout_commit(
            application["repository_url"], commit_sha, repository, temporary_dir,
            credentials["username"], credentials["password"],
        )
        scanner_version, scanner_db_updated, report_path, sbom_path = _run_trivy(repository, output_dir)
    report = _read_json(report_path)
    sbom = _read_json(sbom_path)
    if not isinstance(report, dict) or not isinstance(report.get("Results"), list):
        raise TypeError("Trivy JSON report does not contain a Results array.")
    if not isinstance(sbom, dict) or sbom.get("bomFormat") != "CycloneDX":
        raise TypeError("Trivy did not return a valid CycloneDX SBOM.")
    report_components, trivy_findings = parse_trivy_report(report)
    components = merge_components([*parse_cyclonedx(sbom), *report_components])
    findings, evaluations = combine_findings(components, trivy_findings)
    scan_store.save_scan_result(
        run["run_id"],
        run["lease_token"],
        run["application_id"],
        ref,
        components,
        findings,
        evaluations,
        scanner_version,
        scanner_db_updated,
        str(report_path),
        str(sbom_path),
        _sha256(report_path),
        _sha256(sbom_path),
        application["name"],
    )


def run_worker_once() -> bool:
    callback_processed = inventory_integration.deliver_callback_once()
    run = scan_store.claim_scan(config.SCAN_MAX_ATTEMPTS)
    if not run:
        return callback_processed
    try:
        process_scan(run)
    except (OSError, RuntimeError, TypeError, ValueError, subprocess.SubprocessError, psycopg.Error) as exc:
        message = str(exc)
        log.error("Scan %s failed: %s: %s", run["run_id"], type(exc).__name__, message)
        scan_store.retry_or_fail_scan(
            run["run_id"], run["lease_token"], f"{type(exc).__name__}: {message}", config.SCAN_MAX_ATTEMPTS
        )
    return True


def main():
    if not config.DATABASE_URL:
        raise RuntimeError("VULN_DATABASE_URL is not configured.")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    log.info("Trivy worker started (version %s).", config.TRIVY_VERSION)
    try:
        while True:
            if not run_worker_once():
                time.sleep(config.SCAN_WORKER_POLL_SECONDS)
    except KeyboardInterrupt:
        log.info("Trivy worker stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
