import { test } from 'vitest';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, URL } from 'node:url';
import { main, usage } from '../src/cli.js';

const payload = {
  licenseId: 'LIC-CLI-001',
  product: { id: 'example', version: '5' },
  type: 'subscription',
  customer: { id: 'customer-1', name: 'Acme Corporation' },
  validity: { issuedAt: '2026-09-24T08:00:00Z', expiresAt: '2027-09-24T08:00:00Z' },
  features: [{ id: 'export', enabled: true }],
  limits: [{ id: 'users', value: '50' }],
  machine: { type: 'none' },
};

function capture() {
  let output = '';
  let error = '';
  return {
    io: { stdout: { write: (value) => { output += value; } }, stderr: { write: (value) => { error += value; } } },
    stdout: () => output,
    stderr: () => error,
  };
}

function withWorkspace(run) {
  const directory = mkdtempSync(join(tmpdir(), 'license-xml-cli-'));
  const paths = {
    privateKey: join(directory, 'private.pem'),
    publicKey: join(directory, 'public.pem'),
    payload: join(directory, 'payload.json'),
    license: join(directory, 'license.license.xml'),
  };
  try {
    writeFileSync(paths.payload, JSON.stringify(payload));
    return run(directory, paths);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test('usage covers every command', () => {
  assert.match(usage(), /keygen/);
  assert.match(usage(), /issue/);
  assert.match(usage(), /verify/);
});

test('prints usage for no command and for --help without failing', () => {
  const none = capture();
  assert.equal(main([], none.io), 0);
  assert.match(none.stdout(), /Usage:/);
  const help = capture();
  assert.equal(main(['--help'], help.io), 0);
  const shortHelp = capture();
  assert.equal(main(['-h'], shortHelp.io), 0);
});

test('reports command and option errors with exit code 2', () => {
  for (const argv of [
    ['unknown'],
    ['keygen', '--private'],
    ['keygen', '--private', 'one', '--private', 'two'],
    ['keygen', '--private', 'one', '--public', 'two', '--extra', 'value'],
    ['issue', '--payload', 'payload.json'],
  ]) {
    const captured = capture();
    assert.equal(main(argv, captured.io), 2, argv.join(' '));
    assert.match(captured.stderr(), /Usage:/);
  }
});

test('generates keys, issues a license, and verifies it end to end', () => {
  withWorkspace((directory, paths) => {
    const keygen = capture();
    assert.equal(main(['keygen', '--private', paths.privateKey, '--public', paths.publicKey], keygen.io), 0);
    assert.match(keygen.stdout(), /Wrote private and public keys/);
    assert.match(readFileSync(paths.privateKey, 'utf8'), /PRIVATE KEY/);
    assert.match(readFileSync(paths.publicKey, 'utf8'), /PUBLIC KEY/);

    const issue = capture();
    assert.equal(main(['issue', '--payload', paths.payload, '--private', paths.privateKey, '--key-id', 'test-key', '--out', paths.license], issue.io), 0);
    assert.match(issue.stdout(), /Issued/);

    const verify = capture();
    assert.equal(main([
      'verify', '--file', paths.license, '--key-id', 'test-key', '--public-key', paths.publicKey,
      '--product-id', 'example', '--product-version', '5',
    ], verify.io), 0);
    assert.match(verify.stdout(), /VALID/);

    const mismatch = capture();
    assert.equal(main([
      'verify', '--file', paths.license, '--key-id', 'test-key', '--public-key', paths.publicKey,
      '--product-id', 'other',
    ], mismatch.io), 1);
    assert.match(mismatch.stdout(), /PRODUCT_MISMATCH/);

    const tampered = join(directory, 'tampered.xml');
    writeFileSync(tampered, readFileSync(paths.license, 'utf8').replace('LIC-CLI-001', 'LIC-CLI-002'));
    const invalid = capture();
    assert.equal(main(['verify', '--file', tampered, '--key-id', 'test-key', '--public-key', paths.publicKey], invalid.io), 1);
    assert.match(invalid.stdout(), /INVALID_SIGNATURE/);
  });
});

test('refuses to overwrite existing key files and rolls back partial key writes', () => {
  withWorkspace((directory, paths) => {
    const first = capture();
    assert.equal(main(['keygen', '--private', paths.privateKey, '--public', paths.publicKey], first.io), 0);
    const original = readFileSync(paths.privateKey, 'utf8');

    const repeated = capture();
    assert.equal(main(['keygen', '--private', paths.privateKey, '--public', paths.publicKey], repeated.io), 2);
    assert.equal(readFileSync(paths.privateKey, 'utf8'), original);

    const samePath = capture();
    assert.equal(main(['keygen', '--private', paths.privateKey, '--public', paths.privateKey], samePath.io), 2);

    const rollbackPrivate = join(directory, 'rollback.pem');
    const existingPublic = join(directory, 'existing.pem');
    writeFileSync(existingPublic, 'already exists');
    const rollback = capture();
    assert.equal(main(['keygen', '--private', rollbackPrivate, '--public', existingPublic], rollback.io), 2);
    assert.equal(existsSync(rollbackPrivate), false);
  });
});

test('refuses to overwrite an existing license file', () => {
  withWorkspace((directory, paths) => {
    const keygen = capture();
    main(['keygen', '--private', paths.privateKey, '--public', paths.publicKey], keygen.io);
    const issue = capture();
    assert.equal(main(['issue', '--payload', paths.payload, '--private', paths.privateKey, '--key-id', 'test-key', '--out', paths.license], issue.io), 0);
    const original = readFileSync(paths.license, 'utf8');
    const repeated = capture();
    assert.equal(main(['issue', '--payload', paths.payload, '--private', paths.privateKey, '--key-id', 'test-key', '--out', paths.license], repeated.io), 2);
    assert.equal(readFileSync(paths.license, 'utf8'), original);
  });
});

test('machine-bound licenses verify through the CLI fingerprint option', () => {
  withWorkspace((directory, paths) => {
    const keygen = capture();
    main(['keygen', '--private', paths.privateKey, '--public', paths.publicKey], keygen.io);
    writeFileSync(paths.payload, JSON.stringify({ ...payload, machine: { type: 'fingerprint', value: 'a'.repeat(64) } }));
    const issue = capture();
    assert.equal(main(['issue', '--payload', paths.payload, '--private', paths.privateKey, '--key-id', 'test-key', '--out', paths.license], issue.io), 0);
    const bound = capture();
    assert.equal(main([
      'verify', '--file', paths.license, '--key-id', 'test-key', '--public-key', paths.publicKey,
      '--machine-fingerprint', 'a'.repeat(64),
    ], bound.io), 0);
    assert.match(bound.stdout(), /VALID/);
    const wrong = capture();
    assert.equal(main([
      'verify', '--file', paths.license, '--key-id', 'test-key', '--public-key', paths.publicKey,
      '--machine-fingerprint', 'b'.repeat(64),
    ], wrong.io), 1);
    assert.match(wrong.stdout(), /MACHINE_MISMATCH/);
  });
});

test('the installed binary entry point runs the CLI as a subprocess', () => {
  const cli = fileURLToPath(new URL('../src/cli.js', import.meta.url));
  const result = spawnSync(process.execPath, [cli, '--help'], { encoding: 'utf8' });
  assert.equal(result.status, 0);
  assert.match(result.stdout, /Usage:/);
});
