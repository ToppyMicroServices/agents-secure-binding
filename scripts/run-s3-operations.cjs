// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// Called only by the explicitly opted-in GitHub environment job. Tokens remain
// in private files; the child receives paths and a clean environment.
module.exports = async ({ core }) => {
  const fs = require('node:fs');
  const path = require('node:path');
  const crypto = require('node:crypto');
  const { spawn, execFileSync } = require('node:child_process');
  const minutes = Number(process.env.ASB_S3_OPERATIONS_MINUTES);
  if (![15, 45].includes(minutes)) throw new Error('Unsupported operations duration.');
  const state = '/var/lib/asb-s3-qualification';
  const binaries = '/opt/asb-s3-qualification';
  const staging = path.join(process.env.RUNNER_TEMP, 'asb-aws-private');
  if (fs.existsSync(state) || fs.existsSync(binaries)) throw new Error('Qualification directories already exist.');
  const privileged = (args) => {
    try {
      return execFileSync('sudo', ['-n', ...args], { stdio: ['ignore', 'pipe', 'pipe'], timeout: 15000 });
    } catch {
      throw new Error('Dedicated-user qualification setup or cleanup failed.');
    }
  };
  let owned = false;
  let output = '';
  let child;
  try {
    // useradd fails if this identity already exists. Do not reuse or stop an
    // unrelated account, even on a runner mistakenly configured for this job.
    privileged(['useradd', '--system', '--user-group', '--no-create-home', '--shell', '/usr/sbin/nologin', 'asb-s3']);
    owned = true;
    privileged(['install', '-d', '-o', 'asb-s3', '-g', 'asb-s3', '-m', '0700', state]);
    privileged(['install', '-d', '-o', 'root', '-g', 'root', '-m', '0755', binaries]);
    for (const name of ['asb-s3-live', 'asb-s3-product-live.test']) {
      privileged(['install', '-o', 'root', '-g', 'root', '-m', '0755', path.join(process.env.RUNNER_TEMP, name), path.join(binaries, name)]);
    }
    const fixture = JSON.parse(fs.readFileSync(process.env.ASB_AWS_LIVE_FIXTURE, 'utf8'));
    if (!fixture.specification || !fixture.resource || !fixture.denied_resource || fixture.credentials_file) throw new Error('Explicit OIDC fixture required.');
    fixture.web_identity_token_file = path.join(state, 'oidc.jwt');
    const fixtureStaging = path.join(staging, 'operations-fixture.json');
    fs.writeFileSync(fixtureStaging, JSON.stringify(fixture), { mode: 0o600, flag: 'wx' });
    privileged(['install', '-o', 'asb-s3', '-g', 'asb-s3', '-m', '0600', fixtureStaging, path.join(state, 'fixture.json')]);
    let projections = 0;
    const tokenStaging = path.join(staging, 'renewal.jwt');
    const project = async () => {
      const token = await core.getIDToken('sts.amazonaws.com');
      core.setSecret(token);
      fs.writeFileSync(tokenStaging, token, { mode: 0o600 });
      privileged(['install', '-o', 'asb-s3', '-g', 'asb-s3', '-m', '0600', tokenStaging, path.join(state, 'oidc.next')]);
      privileged(['mv', '-f', '--', path.join(state, 'oidc.next'), fixture.web_identity_token_file]);
      fs.unlinkSync(tokenStaging);
      projections++;
    };
    await project();
    const reportPath = path.join(state, 'result.json');
    const args = ['-n', '-u', 'asb-s3', 'env', '-i', 'PATH=/usr/bin:/bin', 'LANG=C',
      'ASB_AWS_LIVE_CONFIRM=read-explicit-fixture',
      `ASB_AWS_LIVE_FIXTURE=${path.join(state, 'fixture.json')}`,
      `ASB_S3_LIVE_BINARY=${path.join(binaries, 'asb-s3-live')}`,
      `ASB_S3_OPERATIONS_MINUTES=${minutes}`, `ASB_S3_OPERATIONS_REPORT=${reportPath}`,
      '/usr/bin/setpriv', '--no-new-privs', path.join(binaries, 'asb-s3-product-live.test'),
      '-test.run=^TestLiveProductOperations$', '-test.v', `-test.timeout=${minutes + 4}m`];
    child = spawn('sudo', args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let settled = false;
    const collect = (chunk) => {
      if (Buffer.byteLength(output) + chunk.length > 128 * 1024) {
        child.kill('SIGTERM');
        return;
      }
      const text = chunk.toString();
      output += text;
      core.info(text.trimEnd());
    };
    child.stdout.on('data', collect);
    child.stderr.on('data', collect);
    const exited = new Promise((resolve) => {
      child.once('error', () => { settled = true; resolve(-1); });
      child.once('close', (code) => { settled = true; resolve(code ?? -1); });
    });
    const deadline = Date.now() + (minutes + 4) * 60 * 1000;
    while (!settled) {
      let timer;
      await Promise.race([exited, new Promise((resolve) => { timer = setTimeout(resolve, 60000); })]);
      clearTimeout(timer);
      if (!settled) {
        if (Date.now() >= deadline) throw new Error('Operations qualification deadline exceeded.');
        await project();
      }
    }
    const code = await exited;
    if (code !== 0 || !output.includes('--- PASS: TestLiveProductOperations')) throw new Error('Operations gate did not pass.');
    const report = JSON.parse(privileged(['cat', reportPath]).toString());
    if (report.schema !== 'asb.s3-operations-evidence/v1' || report.requested_minutes !== minutes ||
        report.elapsed_seconds < minutes * 60 || report.forced_process_restarts !== 3 || report.observed_token_changes < 2 ||
        report.completed_reads !== minutes * 2 + 2 || !report.nonroot || !report.no_new_privileges || !report.effective_capabilities_zero ||
        !report.oldest_receipt_retained || !report.restart_receipt_without_sts || !report.sealed_backup_restore ||
        !report.retired_authority_denied || !report.restored_authorized_read || report.long_term_qualified !== false ||
        report.physical_power_loss_tested !== false || report.interrupted_aws_effect_tested !== false || report.organization_deployment_qualified !== false) {
      throw new Error('Operations evidence is incomplete.');
    }
    report.commit = process.env.GITHUB_SHA;
    report.run_id = process.env.GITHUB_RUN_ID;
    report.source = 'github-oidc';
    report.token_projections = projections;
    report.binary_sha256 = crypto.createHash('sha256').update(fs.readFileSync(path.join(binaries, 'asb-s3-live'))).digest('hex');
    fs.writeFileSync('evidence/operations-result.json', JSON.stringify(report, null, 2));
  } catch {
    // The Go gate emits bounded diagnostics; do not expose private fixture,
    // token or provisioning error text through the action's exception logger.
    core.setFailed('Dedicated-user operations qualification failed. See the bounded gate log.');
  } finally {
    if (child && child.exitCode === null) child.kill('SIGTERM');
    fs.writeFileSync('evidence/operations-gate.txt', output);
    if (owned) {
      // All processes under this freshly created identity belong to this gate.
      try {
        execFileSync('sudo', ['-n', 'pkill', '-KILL', '-u', 'asb-s3'], { stdio: ['ignore', 'pipe', 'pipe'], timeout: 15000 });
      } catch (error) {
        if (error.status !== 1) throw new Error('Qualification process cleanup failed.');
      }
      privileged(['rm', '-rf', '--', state, binaries]);
      if (fs.existsSync(state) || fs.existsSync(binaries)) throw new Error('Qualification private-file cleanup incomplete.');
      fs.writeFileSync('evidence/operations-cleanup.json', JSON.stringify({ schema: 'asb.s3-operations-cleanup/v1', private_files_removed: true }));
    }
  }
};
