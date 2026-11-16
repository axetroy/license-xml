import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { C14nCanonicalization } from 'xml-crypto';
import {
  MAX_XML_BYTES,
  parseDocument,
  parseLicenseDocument,
  serializePayload,
} from './protocol.js';

const canonicalizer = new C14nCanonicalization();
const IDENTIFIER = /^[a-zA-Z0-9._-]+$/;

export const LicenseStatus = Object.freeze({
  VALID: 'VALID',
  INVALID_FORMAT: 'INVALID_FORMAT',
  INVALID_SIGNATURE: 'INVALID_SIGNATURE',
  PRODUCT_MISMATCH: 'PRODUCT_MISMATCH',
  NOT_YET_VALID: 'NOT_YET_VALID',
  EXPIRED: 'EXPIRED',
  MACHINE_MISMATCH: 'MACHINE_MISMATCH',
});

export function generateKeyPair() {
  return generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
}

export function issueLicense(payload, { keyId, privateKey }) {
  assert(typeof keyId === 'string' && keyId.length <= 128 && IDENTIFIER.test(keyId), 'keyId must be 1–128 letters, digits, dots, underscores, or hyphens');
  assert(typeof privateKey === 'string' || Buffer.isBuffer(privateKey), 'privateKey must be a PEM string or buffer');

  const payloadXml = serializePayload(payload);
  const payloadNode = parseDocument(payloadXml).documentElement;
  const canonicalPayload = canonicalizer.process(payloadNode);
  const signature = sign(null, Buffer.from(canonicalPayload, 'utf8'), createPrivateKey(privateKey)).toString('base64');

  const xml = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<license version="1">',
    payloadXml,
    `  <signature algorithm="Ed25519" keyId="${escapeAttribute(keyId)}">${signature}</signature>`,
    '</license>',
    '',
  ].join('\n');
  assert(Buffer.byteLength(xml, 'utf8') <= MAX_XML_BYTES, 'license XML exceeds the 1 MiB limit');
  return xml;
}

export function parseLicense(xml) {
  const { payload, algorithm, keyId, signature, payloadNode } = parseLicenseDocument(xml);
  return {
    payload,
    algorithm,
    keyId,
    signature: Buffer.from(signature),
    canonicalPayload: canonicalizer.process(payloadNode),
  };
}

export function verifyLicense(xml, options = {}) {
  options = options ?? {};
  let parsed;
  try {
    parsed = parseLicense(xml);
  } catch {
    return { status: LicenseStatus.INVALID_FORMAT };
  }

  if (parsed.algorithm !== 'Ed25519') return { status: LicenseStatus.INVALID_SIGNATURE };
  const publicKey = getPublicKey(options.publicKeys, parsed.keyId);
  if (!publicKey) return { status: LicenseStatus.INVALID_SIGNATURE };

  let signatureIsValid;
  try {
    signatureIsValid = verify(
      null,
      Buffer.from(parsed.canonicalPayload, 'utf8'),
      createPublicKey(publicKey),
      parsed.signature,
    );
  } catch {
    return { status: LicenseStatus.INVALID_SIGNATURE };
  }
  if (!signatureIsValid) return { status: LicenseStatus.INVALID_SIGNATURE };

  const { payload } = parsed;
  if (
    (options.productId !== undefined && payload.product.id !== options.productId) ||
    (options.productVersion !== undefined && payload.product.version !== String(options.productVersion))
  ) {
    return { status: LicenseStatus.PRODUCT_MISMATCH };
  }

  const now = options.now === undefined ? Date.now() : new Date(options.now).getTime();
  if (!Number.isFinite(now)) return { status: LicenseStatus.INVALID_FORMAT };
  if (now < Date.parse(payload.validity.issuedAt)) return { status: LicenseStatus.NOT_YET_VALID };
  if (payload.validity.expiresAt && now >= Date.parse(payload.validity.expiresAt)) {
    return { status: LicenseStatus.EXPIRED };
  }

  if (
    payload.machine.type === 'fingerprint' &&
    (typeof options.machineFingerprint !== 'string' ||
      !/^[a-fA-F0-9]{64}$/.test(options.machineFingerprint) ||
      payload.machine.value.toLowerCase() !== options.machineFingerprint.toLowerCase())
  ) {
    return { status: LicenseStatus.MACHINE_MISMATCH };
  }

  return { status: LicenseStatus.VALID, license: payload };
}

function escapeAttribute(value) {
  return value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('"', '&quot;');
}

function getPublicKey(publicKeys, keyId) {
  if (publicKeys instanceof Map) return publicKeys.get(keyId);
  if (publicKeys && typeof publicKeys === 'object') return Object.hasOwn(publicKeys, keyId) ? publicKeys[keyId] : undefined;
  return undefined;
}

function assert(condition, message) {
  if (!condition) throw new TypeError(message);
}
