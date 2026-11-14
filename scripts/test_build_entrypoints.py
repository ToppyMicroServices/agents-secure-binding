#!/usr/bin/env python3
"""Exercise local build routing and IGVM preflight without Go, Git, or downloads."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MAKE = shutil.which("make")
REVISION = "a" * 40


@unittest.skipUnless(MAKE, "make is required")
class BuildEntrypointTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="asb-build-entrypoints-")
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        self.bin = self.work / "tools"
        self.bin.mkdir()
        self.log = self.work / "calls.jsonl"
        shutil.copyfile(ROOT / "Makefile", self.work / "Makefile")
        self.source = self.work / "reviewed svsm"
        (self.source / "tools/igvmmeasure").mkdir(parents=True)
        helper = self.work / "scripts/igvmmeasure/igvm.sh"
        helper.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / "scripts/igvmmeasure/igvm.sh", helper)
        helper.chmod(0o755)
        self.env = {
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "ASB_TEST_LOG": str(self.log),
            "ASB_TEST_SOURCE": str(self.source),
            "ASB_TEST_HEAD": REVISION,
        }
        self.tool("go", """
if args == ['env', 'GOOS']:
    print('darwin')
elif args == ['env', 'GOARCH']:
    print('arm64')
elif args[0] not in ('build', 'run'):
    sys.exit('unexpected Go call')
""")
        self.tool("git", """
if args[:2] != ['-C', os.environ['ASB_TEST_SOURCE']]:
    sys.exit('unexpected Git access')
command = args[2:]
if command == ['rev-parse', '--verify', 'HEAD']:
    print(os.environ['ASB_TEST_HEAD'])
elif command == ['status', '--porcelain', '--untracked-files=normal', '--ignore-submodules=none']:
    if os.environ.get('ASB_TEST_STATUS_FAIL'):
        sys.exit(1)
    print(os.environ.get('ASB_TEST_DIRTY', ''), end='')
elif command == ['submodule', 'status', '--recursive']:
    print(os.environ.get('ASB_TEST_SUBMODULES', ''), end='')
else:
    sys.exit('unexpected Git operation')
""")
        self.tool("make", """
if args[:3] != ['-C', os.environ['ASB_TEST_SOURCE'], 'bin/igvmmeasure']:
    sys.exit('unexpected upstream build')
binary = Path(os.environ['ASB_TEST_SOURCE']) / 'bin/igvmmeasure'
binary.parent.mkdir(exist_ok=True)
binary.write_text('mock IGVM executable\\n')
""")

    def tool(self, name, body):
        path = self.bin / name
        path.write_text(f"#!{sys.executable}\n" + """
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ['ASB_TEST_LOG'], 'a') as log:
    log.write(json.dumps({'tool': Path(sys.argv[0]).name, 'args': args,
                          'goos': os.environ.get('GOOS'),
                          'goarch': os.environ.get('GOARCH')}) + '\\n')
""" + body)
        path.chmod(0o755)

    def run_make(self, *args, env=None):
        return subprocess.run(
            [MAKE, *args], cwd=self.work, env=self.env | (env or {}),
            text=True, capture_output=True, timeout=10,
        )

    def calls(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_default_build_uses_native_platform_without_external_builds(self):
        result = self.run_make()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        self.assertTrue(all(call['tool'] == 'go' for call in calls), calls)
        builds = [call for call in calls if call['args'][0] == 'build']
        self.assertEqual(len(builds), 6)
        for call in builds:
            self.assertEqual((call['goos'], call['goarch']), ('darwin', 'arm64'))
            self.assertIn('-buildvcs=false', call['args'])

    def test_cli_output_name_and_explicit_cross_compilation(self):
        result = self.run_make('cli', 'GOOS=linux', 'GOARCH=amd64')
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        self.assertEqual(len(calls), 1, calls)
        self.assertEqual(calls[0]['tool'], 'go')
        self.assertEqual((calls[0]['goos'], calls[0]['goarch']), ('linux', 'amd64'))
        self.assertIn('build/agents-secure-binding-cli', calls[0]['args'])

    def test_a2a_build_needs_no_git_metadata(self):
        result = self.run_make('a2a-test')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(all(call['tool'] == 'go' for call in self.calls()))
        build = next(call for call in self.calls() if call['args'][0] == 'build')
        self.assertIn('-s -w -X main.version=dev -X main.commit=unknown', build['args'])

    def igvm(self, revision=REVISION, env=None):
        return self.run_make('build-igvm', f'IGVM_SOURCE_DIR={self.source}',
                             f'IGVM_SOURCE_REVISION={revision}', env=env)

    def assert_no_upstream_build(self):
        self.assertFalse(any(call['tool'] == 'make' for call in self.calls()))

    def test_igvm_requires_explicit_reviewed_input(self):
        result = self.run_make('build-igvm')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('IGVM_SOURCE_DIR', result.stderr)
        self.assertEqual(self.calls(), [])

    def test_igvm_rejects_mutable_revision(self):
        result = self.igvm('main')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('full lowercase', result.stderr)
        self.assertEqual(self.calls(), [])

    def test_igvm_rejects_wrong_revision(self):
        result = self.igvm(env={'ASB_TEST_HEAD': 'b' * 40})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('does not match', result.stderr)
        self.assert_no_upstream_build()

    def test_igvm_rejects_dirty_or_uninspectable_checkout(self):
        for env in ({'ASB_TEST_DIRTY': ' M Cargo.lock\n'}, {'ASB_TEST_STATUS_FAIL': '1'}):
            with self.subTest(env=env):
                result = self.igvm(env=env)
                self.assertNotEqual(result.returncode, 0)
                self.assert_no_upstream_build()

    def test_igvm_rejects_uninitialized_or_changed_submodule(self):
        for marker in ('-', '+', 'U'):
            with self.subTest(marker=marker):
                result = self.igvm(env={'ASB_TEST_SUBMODULES': f'{marker}{REVISION} dependency\n'})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('pinned revisions', result.stderr)
                self.assert_no_upstream_build()

    def test_igvm_builds_only_matching_clean_local_source(self):
        result = self.igvm(env={'ASB_TEST_SUBMODULES': f' {REVISION} dependency\n'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.work / 'build/igvmmeasure').read_text(), 'mock IGVM executable\n')
        self.assertEqual([call['tool'] for call in self.calls()], ['git', 'git', 'git', 'make'])


if __name__ == '__main__':
    unittest.main()
