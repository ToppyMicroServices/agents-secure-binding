#!/usr/bin/env python3
"""Round-trip actual Linux apt candidates through the Pages publication gate."""
import argparse
import importlib.util
from pathlib import Path
import shutil
import sys
import tempfile

spec = importlib.util.spec_from_file_location("asb_pages", Path(__file__).with_name("asb-apt-pages.py"))
pages = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pages)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "linux":
        raise ValueError("run publication integration checks on Linux")
    build = args.build.resolve()
    lifecycle = pages.apt.strict_json(pages.apt.read(build / "apt-lifecycle.json"))
    if lifecycle.get("passed") is not True:
        raise ValueError("apt lifecycle did not pass")
    metadata = build / "apt-lifecycle.evidence"
    keyring = metadata / "keyrings/b.gpg"
    public_policy = {"schema": "asb.apt-pages-policy/v1", "base_url": pages.BASE_URL,
               "signers": [lifecycle["ephemeral_test_key_fingerprints"]["b"]],
               "keyring_sha256": pages.apt.sha(pages.apt.read(keyring))}
    output = build / "apt-pages"
    output.mkdir()
    pages.write_new(output / "test-policy.json", pages.apt.encoded(public_policy))
    public_policy = pages.policy(output / "test-policy.json")
    with tempfile.TemporaryDirectory(prefix="asb-pages-roundtrip-") as temp:
        root = Path(temp)
        repository = root / "repository"
        shutil.copytree(metadata / "upgrade/dists", repository / "dists")
        manifest = pages.apt.strict_json(pages.apt.read(repository / pages.apt.DIST / "manifest.json"))
        source = manifest["source_commit"]
        for package in manifest["packages"]:
            payload = pages.apt.read(build / "debian-upgrade" / Path(package["path"]).name, pages.apt.MAX_PACKAGE)
            pages.write_new(repository / package["path"], payload)
        stage = pages.stage(repository, keyring, public_policy, source, root / "site")
        archive = output / "asb-apt-site.tar"
        packed = pages.pack(root / "site", public_policy, source, archive)
        pages.unpack(archive, packed["sha256"], root / "unpacked")
        checked = pages.verify_site(root / "unpacked", public_policy, source)
        if pages.file_map(root / "site") != pages.file_map(root / "unpacked"):
            raise ValueError("final archive changed publication bytes")
        report = {"schema": "asb.apt-pages-roundtrip/v1", "passed": True, "stage": stage,
                  "archive": packed, "verified_final_archive": checked, "source_commit": source,
                  "limits": ["ephemeral CI signing key", "not published", "HTTPS readback not exercised"]}
        pages.write_new(output / "report.json", pages.apt.encoded(report))
    print(pages.apt.encoded(report).decode(), end="")


if __name__ == "__main__":
    main()
