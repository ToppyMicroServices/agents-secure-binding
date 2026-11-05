#!/usr/bin/env python3
"""Renew an approved APT payload; private-key operations stay attended and local."""
import argparse
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from urllib.request import HTTPSHandler, Request, build_opener

spec = importlib.util.spec_from_file_location("renewal_pages", Path(__file__).with_name("asb-apt-pages.py"))
pages = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pages)
apt = pages.apt
REPO = "ToppyMicroServices/agents-secure-binding"
ROOT = Path(__file__).resolve().parents[1]
TITLE = "ASB APT renewal: monthly signing and expiry"
TAG = r"apt-preview-renewal-[0-9]{8}-[0-9]{10}"
MARKER = r"<!-- asb-apt-renewal-state: (\{[^\n]+\}) -->"


def require(value, message):
    if not value:
        raise ValueError(message)


def now():
    return int(datetime.now(timezone.utc).timestamp())


def month(timestamp):
    return datetime.fromtimestamp(timestamp, timezone(timedelta(hours=9))).strftime("%Y-%m")


def policy(path):
    value = apt.strict_json(apt.read(path))
    fields = {"schema", "baseline_release", "baseline_sha256", "baseline_bytes", "source_commit",
              "version", "payload_sha256", "validity_days", "notify_assignee", "notification_issue"}
    require(set(value) == fields and value["schema"] == "asb.apt-renewal-policy/v1", "invalid renewal policy")
    require(isinstance(value["baseline_release"], str) and re.fullmatch(r"apt-preview-[A-Za-z0-9._-]{1,80}", value["baseline_release"]), "invalid baseline tag")
    for key, length in (("source_commit", 40), ("baseline_sha256", 64), ("payload_sha256", 64)):
        require(isinstance(value[key], str) and re.fullmatch("[0-9a-f]{%d}" % length, value[key]), "invalid renewal digest")
    require(type(value["baseline_bytes"]) is int and 0 < value["baseline_bytes"] <= pages.MAX_SITE,
            "invalid baseline size")
    require(type(value["validity_days"]) is int and value["validity_days"] == 45, "renewal requires exactly 45 days")
    require(type(value["notification_issue"]) is int and value["notification_issue"] > 0, "notification issue is required")
    require(isinstance(value["notify_assignee"], str) and re.fullmatch(r"[A-Za-z0-9-]{1,39}", value["notify_assignee"]), "invalid notification assignee")
    return value


def payload_digest(manifest):
    return apt.sha(apt.encoded({k: v for k, v in manifest.items() if k not in ("created", "expires")}))


def check_payload(manifest, approved, fresh=False):
    apt.validate_manifest(manifest)
    require(manifest["source_commit"] == approved["source_commit"] and manifest["version"] == approved["version"]
            and payload_digest(manifest) == approved["payload_sha256"], "payload differs from reviewed renewal policy")
    if fresh:
        apt.validate_dates(manifest["created"], manifest["expires"], now())
        require(manifest["expires"] - manifest["created"] == 45 * 86400, "renewal must have 45-day validity")
        require(now() - manifest["created"] <= 7 * 86400, "signing preparation is older than seven days")


def gh(*args, payload=None):
    command = ["gh", *args]
    result = subprocess.run(command, input=None if payload is None else json.dumps(payload).encode(),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180, check=True)
    return result.stdout


def api(path, payload=None, method=None):
    args = ["api", "repos/" + REPO + "/" + path]
    if method:
        args += ["--method", method]
    if payload is not None:
        args += ["--input", "-"]
    output = gh(*args, payload=payload)
    return json.loads(output) if output.strip() else None


def release_asset(release, tag, digest=None, size=None):
    require(release.get("tag_name") == tag and release.get("draft") is False
            and release.get("prerelease") is True and release.get("immutable") is True,
            "use an immutable published Preview release")
    assets = release.get("assets")
    require(isinstance(assets, list) and len(assets) == 1, "release must contain only the reviewed site archive")
    asset = assets[0]
    require(asset.get("name") == "asb-apt-site.tar" and type(asset.get("size")) is int
            and 0 < asset["size"] <= pages.MAX_SITE and isinstance(asset.get("digest"), str)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", asset["digest"]), "invalid release asset")
    require((digest is None or asset["digest"] == "sha256:" + digest)
            and (size is None or asset["size"] == size), "release asset differs from approved baseline")
    return asset


def download(tag, destination):
    gh("release", "download", tag, "--repo", REPO, "--pattern", "asb-apt-site.tar", "--dir", str(destination))
    return destination / "asb-apt-site.tar"


def prepare(approved, public, archive, output):
    require(not output.exists() and not output.is_symlink(), "preparation output must be new")
    require(archive.stat().st_size == approved["baseline_bytes"], "baseline size differs")
    with tempfile.TemporaryDirectory(prefix="asb-renewal-base-") as temporary:
        captured = Path(temporary) / "baseline"
        pages.unpack(archive, approved["baseline_sha256"], captured)
        # Expired baseline dates are historical here. Its complete immutable
        # archive hash is independently approved; it is never published as fresh.
        manifest = apt.inspect_repository(captured / "apt")
        check_payload(manifest, approved)
        key = apt.read(captured / "asb-archive.gpg")
        pages.public_keyring(key, public)
        created = now()
        manifest = dict(manifest, created=created, expires=created + 45 * 86400)
        files = apt.metadata(manifest)
        for item in manifest["packages"]:
            files[item["path"]] = apt.read(captured / "apt" / item["path"], apt.MAX_PACKAGE)
        for name, data in files.items():
            pages.write_new(output / "repository" / name, data)
        pages.write_new(output / "asb-archive.gpg", key)
        plan = {"schema": "asb.apt-renewal-preparation/v1", "source_commit": manifest["source_commit"],
                "version": manifest["version"], "created": created, "expires": manifest["expires"],
                "baseline_sha256": approved["baseline_sha256"], "payload_sha256": approved["payload_sha256"],
                "manifest_sha256": apt.sha(apt.encoded(manifest))}
        pages.write_new(output / "signing-plan.json", apt.encoded(plan))
    validate_prepared(output, approved, public)
    return plan


def validate_prepared(root, approved, public):
    manifest = apt.inspect_repository(root / "repository")
    check_payload(manifest, approved, fresh=True)
    files = pages.file_map(root)
    expected = {"repository/" + name for name in apt.metadata(manifest)}
    expected |= {"repository/" + item["path"] for item in manifest["packages"]}
    require(set(files) == expected | {"asb-archive.gpg", "signing-plan.json"}, "unexpected preparation file or signature")
    pages.public_keyring(files["asb-archive.gpg"], public)
    plan = apt.strict_json(files["signing-plan.json"])
    expected_plan = {"schema": "asb.apt-renewal-preparation/v1", "source_commit": manifest["source_commit"],
                     "version": manifest["version"], "created": manifest["created"], "expires": manifest["expires"],
                     "baseline_sha256": approved["baseline_sha256"], "payload_sha256": approved["payload_sha256"],
                     "manifest_sha256": apt.sha(apt.encoded(manifest))}
    require(plan == expected_plan, "signing plan differs from captured payload")
    return manifest


def validate_signed(site, approved, public):
    result = pages.verify_site(site, public, approved["source_commit"])
    check_payload(apt.inspect_repository(site / "apt"), approved, fresh=True)
    return result


def hardware_sign(repository, home, identity, prompt=input, announce=print):
    require(home.is_absolute() and home.is_dir() and not home.is_symlink() and not home.stat().st_mode & 0o077,
            "use an explicit existing 0700 GnuPG home")
    release = repository / apt.DIST / "Release"
    # Only this block can contact a token. No retries, PIN overrides or settings.
    try:
        prompt("Connect the signing YubiKey with its authentication window attended, then press Enter: ")
        deadline = time.monotonic() + 180

        def run(*args):
            timeout = deadline - time.monotonic()
            require(timeout > 0, "attended signing timed out")
            return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=True).stdout.decode()

        listing = run("gpg", "--homedir", str(home), "--batch", "--with-colons", "--with-keygrip", "--list-keys", identity)
        current, grips = None, []
        for line in listing.splitlines():
            item = line.split(":")
            if item[0] == "fpr":
                current = item[9]
            elif item[0] == "grp" and current == identity:
                grips.append(item[9])
        require(len(grips) == 1 and re.fullmatch(r"[0-9A-F]{40}", grips[0]), "signer keygrip does not match")
        info = run("gpg-connect-agent", "--homedir", str(home), "KEYINFO " + grips[0], "/bye")
        matches = [line.split() for line in info.splitlines() if line.startswith("S KEYINFO ")]
        require(len(matches) == 1 and len(matches[0]) >= 4 and matches[0][2:4] == [grips[0], "T"],
                "approved signer is not a hardware-token reference")
        for name, kind in (("InRelease", "--clearsign"), ("Release.gpg", "--detach-sign")):
            run("gpg", "--homedir", str(home), "--batch", "--no-tty", "--local-user", identity + "!",
                "--digest-algo", "SHA256", "--output", str(repository / apt.DIST / name), kind, str(release))
    finally:
        announce("Signing session ended. REMOVE THE YUBIKEY NOW. No further token access is needed.")


def sign(prepared, output, home, approved, public, identity):
    require(identity in public["signers"], "signer is not approved")
    require(not output.exists() and not output.is_symlink(), "signed archive output must be new")
    with pages.snapshot_site(prepared) as captured:
        validate_prepared(captured, approved, public)
        hardware_sign(captured / "repository", home, identity)
        site = captured / "site"
        pages.stage(captured / "repository", captured / "asb-archive.gpg", public, approved["source_commit"], site)
        validate_signed(site, approved, public)
        return pages.pack(site, public, approved["source_commit"], output)


def upload(archive, approved, public):
    with tempfile.TemporaryDirectory(prefix="asb-renewal-upload-") as temporary:
        root = Path(temporary)
        data = apt.read(archive, pages.MAX_SITE)
        fixed = root / "asb-apt-site.tar"
        fixed.write_bytes(data)
        site = root / "site"
        pages.unpack(fixed, apt.sha(data), site)
        validate_signed(site, approved, public)
        manifest = apt.inspect_repository(site / "apt")
        tag = "apt-preview-renewal-" + datetime.fromtimestamp(manifest["created"], timezone.utc).strftime("%Y%m%d") + "-" + str(manifest["created"])
        notes = root / "notes.md"
        notes.write_text("ASB Preview APT metadata renewal.\n\nArchive SHA-256: `" + apt.sha(data)
                         + "`\n\nSource: `" + approved["source_commit"] + "`\n\nPackage payload unchanged. Production verification is recorded in the ASB apt Pages publication workflow. This asset alone does not establish verified delivery.\n")
        head = api("git/ref/heads/main")["object"]["sha"]
        require(re.fullmatch(r"[0-9a-f]{40}", head), "invalid main commit")
        gh("release", "create", tag, str(fixed), "--repo", REPO, "--target", head, "--draft", "--prerelease",
           "--latest=false", "--title", "ASB Preview APT renewal " + tag[20:], "--notes-file", str(notes))
        gh("release", "edit", tag, "--repo", REPO, "--draft=false")
        api("actions/workflows/apt-renewal.yaml/dispatches", {"ref": "main", "inputs": {"operation": "submit", "release_tag": tag}})
        return {"release_tag": tag, "sha256": apt.sha(data), "publication": "automatic verification queued"}


def submit(tag, approved, public):
    require(isinstance(tag, str) and re.fullmatch(TAG, tag), "invalid renewal release tag")
    asset = release_asset(api("releases/tags/" + tag), tag)
    with tempfile.TemporaryDirectory(prefix="asb-renewal-submit-") as temporary:
        root = Path(temporary)
        archive = download(tag, root)
        require(archive.stat().st_size == asset["size"], "download size differs")
        site = root / "site"
        pages.unpack(archive, asset["digest"][7:], site)
        validate_signed(site, approved, public)
        manifest = apt.inspect_repository(site / "apt")
        expected = "apt-preview-renewal-" + datetime.fromtimestamp(manifest["created"], timezone.utc).strftime("%Y%m%d") + "-" + str(manifest["created"])
        require(tag == expected, "release tag differs from signed creation date")
        api("actions/workflows/apt-pages.yaml/dispatches", {"ref": "main", "inputs": {
            "release_tag": tag, "archive_sha256": asset["digest"][7:], "source_commit": approved["source_commit"]}})
    return {"dispatched": True, "release_tag": tag, "sha256": asset["digest"][7:]}


def expiry_state(manifest, timestamp):
    require(manifest["created"] <= timestamp + 10, "published metadata is dated in the future")
    remaining = manifest["expires"] - timestamp
    if remaining <= 0:
        return "expired"
    if remaining <= 7 * 86400:
        return "urgent"
    if remaining <= 14 * 86400:
        return "warning"
    return "ready" if month(timestamp) != month(manifest["created"]) else "healthy"


def monitor(approved, public):
    with tempfile.TemporaryDirectory(prefix="asb-renewal-monitor-") as temporary:
        root = Path(temporary)
        opener = build_opener(HTTPSHandler(), pages.NoRedirect())
        names = ["asb-archive.gpg"] + ["apt/" + str(apt.DIST / name) for name in ("Release", "InRelease", "Release.gpg", "manifest.json")]
        for name in names:
            uri = public["base_url"] + "/" + name
            request = Request(uri, headers={"User-Agent": "ASB-publication-verifier", "Accept-Encoding": "identity"})
            with opener.open(request, timeout=30) as response:
                require(response.status == 200 and response.geturl() == uri
                        and response.headers.get("Content-Encoding", "identity") == "identity", "unexpected monitor response")
                data = response.read(apt.MAX_METADATA + 1)
                require(len(data) <= apt.MAX_METADATA, "monitor response exceeds bound")
            pages.write_new(root / name, data)
        keyring = root / "asb-archive.gpg"
        pages.public_keyring(apt.read(keyring), public)
        _, release = apt.verify_signatures(root / "apt", keyring, public["signers"])
        manifest_bytes = apt.read(root / "apt" / apt.DIST / "manifest.json")
        manifest = apt.strict_json(manifest_bytes)
        check_payload(manifest, approved)
        require(apt.encoded(manifest) == manifest_bytes
                and apt.metadata(manifest)[str(apt.DIST / "Release")] == release, "monitor manifest is not authenticated")
        return {"state": expiry_state(manifest, now()), "expires": manifest["expires"], "created": manifest["created"]}


def notify(approved, state, detail, cycle=None):
    require(state in ("ready", "warning", "urgent", "expired", "error", "healthy"), "invalid notification state")
    cycle = cycle or month(now())
    issue = "issues/" + str(approved["notification_issue"])
    current = api(issue)
    require(current.get("title") == TITLE and "pull_request" not in current, "notification issue identity differs")
    marker = re.search(MARKER, current.get("body") or "")
    try:
        previous = json.loads(marker[1]) if marker else None
    except ValueError:
        previous = None
    desired = {"state": state, "cycle": cycle}
    if previous == desired and current["state"] == ("closed" if state == "healthy" else "open"):
        return {"notification": "unchanged", **desired}
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    run = "https://github.com/" + REPO + "/actions/runs/" + run_id if run_id.isdigit() else "See the APT renewal workflow."
    body = ("Monthly attended APT renewal; 45-day metadata validity.\n\nStatus: **" + state + "**\n\n"
            + detail + "\n\n" + run + "\n\nConnect YubiKey only when the signing helper prompts; remove it immediately afterward.\n"
            + "\n<!-- asb-apt-renewal-state: " + json.dumps(desired, sort_keys=True) + " -->\n")
    api(issue, {"body": body, "state": "closed" if state == "healthy" else "open",
                "assignees": [approved["notify_assignee"]]}, method="PATCH")
    api(issue + "/comments", {"body": "APT renewal status: **" + state + "** (" + cycle + ").\n\n" + detail + "\n\n" + run})
    return {"notification": "updated", **desired}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "sign", "upload", "submit", "monitor", "validate", "notify"))
    parser.add_argument("--policy", type=Path, default=ROOT / "packaging/debian/apt-renewal.json")
    parser.add_argument("--public-policy", type=Path, default=ROOT / "packaging/debian/archive-signers.json")
    parser.add_argument("--input", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--gnupg-home", type=Path)
    parser.add_argument("--signer")
    parser.add_argument("--publish", action="store_true")
    parser.add_argument("--release-tag")
    parser.add_argument("--state", choices=("ready", "warning", "urgent", "expired", "error", "healthy"))
    parser.add_argument("--detail", default="See the workflow evidence and monthly signing instructions.")
    args = parser.parse_args()
    try:
        approved, public = policy(args.policy), pages.policy(args.public_policy)
        if args.command in ("sign", "upload", "validate"):
            require(args.input is not None, "--input is required")
        if args.command in ("prepare", "sign"):
            require(args.output is not None, "--output is required")
        if args.command == "sign":
            require(args.gnupg_home is not None, "--gnupg-home is required")
        if args.command == "prepare":
            release_asset(api("releases/tags/" + approved["baseline_release"]), approved["baseline_release"],
                          approved["baseline_sha256"], approved["baseline_bytes"])
            with tempfile.TemporaryDirectory(prefix="asb-renewal-download-") as temporary:
                result = prepare(approved, public, download(approved["baseline_release"], Path(temporary)), args.output)
        elif args.command == "sign":
            result = sign(args.input, args.output, args.gnupg_home, approved, public, args.signer or public["signers"][0])
            if args.publish:
                result = result | upload(args.output, approved, public)
        elif args.command == "upload":
            result = upload(args.input, approved, public)
        elif args.command == "submit":
            result = submit(args.release_tag, approved, public)
        elif args.command == "validate":
            result = validate_signed(args.input, approved, public)
        elif args.command == "notify":
            result = notify(approved, args.state, args.detail)
        else:
            try:
                result = monitor(approved, public)
            except (ValueError, OSError, TypeError, KeyError, subprocess.SubprocessError):
                notify(approved, "error", "Published metadata could not be authenticated. Inspect the failed workflow; freshness is unknown.")
                raise
            expires = datetime.fromtimestamp(result["expires"], timezone.utc).isoformat()
            result |= notify(approved, result["state"], "Authenticated metadata expiry: **" + expires + "**. Download the latest monthly preparation from the workflow before signing.")
        print(json.dumps(result, sort_keys=True))
    except (ValueError, OSError, TypeError, KeyError, EOFError, KeyboardInterrupt, subprocess.SubprocessError) as error:
        detail = str(error) if type(error) is ValueError else type(error).__name__
        print("APT renewal failed: " + detail, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
