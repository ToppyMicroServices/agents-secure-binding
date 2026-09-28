// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// Opt-in disposable Linux runner only. The service receives token paths, never
// the runner's OIDC request credential or an ambient AWS credential chain.
module.exports = async ({ core }) => {
  const fs = require('node:fs');
  const path = require('node:path');
  const crypto = require('node:crypto');
  const { spawn, execFileSync } = require('node:child_process');
  const state = '/var/lib/asb-s3';
  const config = '/etc/asb-s3';
  const binaries = '/opt/asb-s3-systemd-qualification';
  const service = '/etc/systemd/system/asb-s3.service';
  const installed = '/usr/local/bin/asb-s3';
  const journal = '/etc/systemd/journald@asb-s3.conf.d';
  const staging = path.join(process.env.RUNNER_TEMP, 'asb-aws-private');
  const ownedPaths = [state, config, binaries, service, installed, journal];
  const existingConfiguration = [...ownedPaths, '/etc/systemd/system/asb-s3.service.d'];
  if (process.env.ASB_S3_OPERATIONS_MINUTES !== '0' || existingConfiguration.some(p => fs.existsSync(p))) {
    throw new Error('Live systemd qualification requires a fresh isolated runner and operations_minutes=0.');
  }
  const privileged = (args) => {
    try {
      return execFileSync('sudo', ['-n', ...args], { stdio: ['ignore', 'pipe', 'pipe'], timeout: 70000 });
    } catch {
      throw new Error('Live systemd qualification setup or cleanup failed.');
    }
  };
  let owned = false;
  let child;
  let exited;
  let output = '';
  try {
    privileged(['useradd', '--system', '--user-group', '--no-create-home', '--shell', '/usr/sbin/nologin', 'asb-s3']);
    owned = true;
    privileged(['install', '-d', '-o', 'asb-s3', '-g', 'asb-s3', '-m', '0700', state, config, path.join(state, 'qa')]);
    privileged(['install', '-d', '-m', '0755', binaries, journal]);
    privileged(['install', '-m', '0755', path.join(process.env.RUNNER_TEMP, 'asb-s3-live'), installed]);
    const testBinary = path.join(binaries, 'asb-s3-product-live.test');
    privileged(['install', '-m', '0755', path.join(process.env.RUNNER_TEMP, 'asb-s3-product-live.test'), testBinary]);
    privileged(['install', '-m', '0644', 'packaging/s3/asb-s3.service', service]);
    privileged(['install', '-m', '0644', 'packaging/s3/journald-asb-s3.conf', path.join(journal, 'retention.conf')]);
    const fixture = JSON.parse(fs.readFileSync(process.env.ASB_AWS_LIVE_FIXTURE, 'utf8'));
    if (!fixture.specification || !fixture.resource || !fixture.denied_resource || fixture.credentials_file) throw new Error('Explicit OIDC fixture required.');
    fixture.web_identity_token_file = path.join(state, 'oidc.jwt');
    const fixtureStaging = path.join(staging, 'systemd-fixture.json');
    fs.writeFileSync(fixtureStaging, JSON.stringify(fixture), { mode: 0o600, flag: 'wx' });
    privileged(['install', '-o', 'asb-s3', '-g', 'asb-s3', '-m', '0600', fixtureStaging, path.join(state, 'fixture.json')]);
    const project = async () => {
      const token = await core.getIDToken('sts.amazonaws.com');
      core.setSecret(token);
      const temporary = path.join(staging, 'systemd-renewal.jwt');
      fs.writeFileSync(temporary, token, { mode: 0o600, flag: 'wx' });
      privileged(['install', '-o', 'asb-s3', '-g', 'asb-s3', '-m', '0600', temporary, path.join(state, 'oidc.next')]);
      privileged(['mv', '-f', '--', path.join(state, 'oidc.next'), fixture.web_identity_token_file]);
      fs.unlinkSync(temporary);
    };
    await project();
    child = spawn('sudo', ['-n', 'timeout', '--signal=TERM', '--kill-after=10s', '17m',
      'env', '-i', 'PATH=/usr/bin:/bin', 'LANG=C', 'TMPDIR=/var/lib/asb-s3/qa',
      'ASB_AWS_LIVE_CONFIRM=read-explicit-fixture', 'ASB_S3_SYSTEMD_LIVE=1',
      `ASB_AWS_LIVE_FIXTURE=${path.join(state, 'fixture.json')}`, `ASB_S3_LIVE_BINARY=${installed}`,
      testBinary, '-test.run=^TestLiveSystemdIdentityRecovery$', '-test.v', '-test.timeout=16m'],
    { stdio: ['ignore', 'pipe', 'pipe'] });
    let settled = false;
    let overflow = false;
    const collect = chunk => {
      if (Buffer.byteLength(output) + chunk.length > 128 * 1024) {
        overflow = true;
        child.kill('SIGTERM');
        return;
      }
      const text = chunk.toString();
      output += text;
      core.info(text.trimEnd());
    };
    child.stdout.on('data', collect);
    child.stderr.on('data', collect);
    exited = new Promise(resolve => {
      child.once('error', () => { settled = true; resolve(-1); });
      child.once('close', code => { settled = true; resolve(code ?? -1); });
    });
    const deadline = Date.now() + 18 * 60 * 1000;
    let renewed = false;
    while (!settled) {
      let timer;
      await Promise.race([exited, new Promise(resolve => { timer = setTimeout(resolve, 1000); })]);
      clearTimeout(timer);
      if (settled) break;
      if (Date.now() >= deadline || overflow) throw new Error('Bounded systemd gate exceeded its limit.');
      // A root-only marker requests one deliberate renewal after expiry denial.
      const pending = privileged(['find', state, '-maxdepth', '1', '-name', 'renew-request', '-type', 'f', '-printf', 'ready']).toString();
      if (!renewed && pending === 'ready') {
        await project();
        privileged(['touch', path.join(state, 'renew-ready')]);
        renewed = true;
      }
    }
    if (await exited !== 0 || overflow || !renewed || !output.includes('--- PASS: TestLiveSystemdIdentityRecovery')) {
      throw new Error('Live systemd identity gate did not pass.');
    }
    const report = JSON.parse(privileged(['cat', path.join(state, 'systemd-result.json')]).toString());
    const required = ['installed_unit', 'nonroot', 'no_new_privileges', 'effective_capabilities_zero', 'initial_authorized_read',
      'natural_expiry_denied', 'atomic_identity_renewal', 'same_process_recovered', 'renewed_authorized_read',
      'old_operation_conflict', 'first_receipt_retained', 'service_stopped'];
    if (report.schema !== 'asb.s3-systemd-live-evidence/v1' || required.some(key => report[key] !== true) ||
        report.completed_reads !== 2 || report.uncertain_records !== 1 ||
        !['ExpiredToken', 'InvalidIdentityToken (token_expired)'].includes(report.aws_expiry_code) ||
        report.organization_deployment_qualified !== false || report.physical_power_loss_tested !== false) {
      throw new Error('Live systemd evidence is incomplete.');
    }
    report.commit = process.env.GITHUB_SHA;
    report.run_id = process.env.GITHUB_RUN_ID;
    report.source = 'github-oidc';
    report.binary_sha256 = crypto.createHash('sha256').update(fs.readFileSync(installed)).digest('hex');
    fs.writeFileSync('evidence/systemd-result.json', JSON.stringify(report, null, 2));
  } catch {
    core.setFailed('Live systemd identity qualification failed. See the bounded gate log.');
  } finally {
    if (child && child.exitCode === null) child.kill('SIGTERM');
    if (exited) {
      let timer;
      await Promise.race([exited, new Promise(resolve => { timer = setTimeout(resolve, 10000); })]);
      clearTimeout(timer);
      if (child.exitCode === null) child.kill('SIGKILL');
    }
    fs.writeFileSync('evidence/systemd-gate.txt', output);
    if (owned) {
      if (fs.existsSync(service)) privileged(['systemctl', 'disable', '--now', 'asb-s3.service']);
      try {
        execFileSync('sudo', ['-n', 'pkill', '-KILL', '-u', 'asb-s3'], { stdio: ['ignore', 'pipe', 'pipe'], timeout: 15000 });
      } catch (error) {
        if (error.status !== 1) throw new Error('Qualification process cleanup failed.');
      }
      privileged(['rm', '-rf', '--', ...ownedPaths]);
      privileged(['systemctl', 'daemon-reload']);
      if (ownedPaths.some(p => fs.existsSync(p))) throw new Error('Qualification private-file cleanup incomplete.');
      fs.writeFileSync('evidence/systemd-cleanup.json', JSON.stringify({ schema: 'asb.s3-systemd-cleanup/v1', private_files_removed: true, service_removed: true }));
    }
  }
};
