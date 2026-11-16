#!/usr/bin/env node
import { generateKeyPair, issueLicense, verifyLicense } from './index.js';
import { readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

export function usage() {
  return `Usage:
   license-xml keygen --private private.pem --public public.pem
   license-xml issue --payload payload.json --private private.pem --key-id ID --out license.license.xml
   license-xml verify --file license.license.xml --key-id ID --public-key public.pem [--product-id ID] [--product-version N] [--machine-fingerprint SHA256]`;
}

function parseOptions(args) {
  const options = {};
  for (let index = 0; index < args.length; index += 1) {
    const key = args[index];
    if (!key.startsWith('--') || options[key.slice(2)] !== undefined) throw new Error(`Unexpected or repeated option: ${key}`);
    const value = args[index + 1];
    if (!value || value.startsWith('--')) throw new Error(`Missing value for ${key}`);
    options[key.slice(2)] = value;
    index += 1;
  }
  return options;
}

function required(options, names) {
  for (const name of names) {
    if (!options[name]) throw new Error(`Missing --${name}`);
  }
}

function writeNewFile(path, content, mode = 0o644) {
  writeFileSync(path, content, { flag: 'wx', mode });
}

function run(argv, { stdout }) {
  const [command, ...args] = argv;
  if (!command || command === '--help' || command === '-h') {
    stdout.write(`${usage()}\n`);
    return 0;
  }
  const options = parseOptions(args);
  const allowed = {
    keygen: ['private', 'public'],
    issue: ['payload', 'private', 'key-id', 'out'],
    verify: ['file', 'key-id', 'public-key', 'product-id', 'product-version', 'machine-fingerprint'],
  }[command];
  if (!allowed) throw new Error(`Unknown command: ${command}`);
  if (Object.keys(options).some((name) => !allowed.includes(name))) throw new Error('Unknown option for command');

  if (command === 'keygen') {
    required(options, ['private', 'public']);
    if (options.private === options.public) throw new Error('Private and public key paths must be different');
    const keys = generateKeyPair();
    writeNewFile(options.private, keys.privateKey, 0o600);
    try {
      writeNewFile(options.public, keys.publicKey);
    } catch (error) {
      unlinkSync(options.private);
      throw error;
    }
    stdout.write(`Wrote private and public keys.\n`);
    return 0;
  }

  if (command === 'issue') {
    required(options, ['payload', 'private', 'key-id', 'out']);
    const payload = JSON.parse(readFileSync(options.payload, 'utf8'));
    const license = issueLicense(payload, { keyId: options['key-id'], privateKey: readFileSync(options.private) });
    writeNewFile(options.out, license);
    stdout.write(`Issued ${options.out}\n`);
    return 0;
  }

  if (command === 'verify') {
    required(options, ['file', 'key-id', 'public-key']);
    const xml = readFileSync(options.file, 'utf8');
    const result = verifyLicense(xml, {
      publicKeys: new Map([[options['key-id'], readFileSync(options['public-key'])]]),
      productId: options['product-id'],
      productVersion: options['product-version'],
      machineFingerprint: options['machine-fingerprint'],
    });
    stdout.write(`${result.status}\n`);
    return result.status === 'VALID' ? 0 : 1;
  }
}

export function main(argv, io = { stdout: process.stdout, stderr: process.stderr }) {
  try {
    return run(argv, io);
  } catch (error) {
    io.stderr.write(`${error.message}\n${usage()}\n`);
    return 2;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = main(process.argv.slice(2));
}
