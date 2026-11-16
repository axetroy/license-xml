import { test } from 'vitest';
import assert from 'node:assert/strict';
import { C14nCanonicalization } from 'xml-crypto';
import { XmlCanonicalizer } from 'xmldsigjs';
import { parseDocument, parseLicenseDocument, serializePayload } from '../src/protocol.js';
import { generateKeyPair, issueLicense, parseLicense, verifyLicense, LicenseStatus } from '../src/index.js';

const { privateKey, publicKey } = generateKeyPair();
const publicKeys = new Map([['test-key', publicKey]]);
const now = new Date('2026-09-24T08:00:00Z');
const subscription = {
  licenseId: 'LIC-001',
  product: { id: 'example', version: '5' },
  type: 'subscription',
  customer: { id: 'customer-1', name: 'Acme Corporation' },
  validity: { issuedAt: '2026-09-24T08:00:00Z', expiresAt: '2027-09-24T08:00:00Z' },
  features: [{ id: 'export', enabled: true }, { id: 'sso', enabled: false }],
  limits: [{ id: 'users', value: '50' }],
  machine: { type: 'none' },
};

test('playground and Node.js canonicalizers agree on signed payloads', () => {
  const xml = issueLicense(subscription, { keyId: 'test-key', privateKey });
  const payloadNode = parseDocument(serializePayload(subscription)).documentElement;
  const nodeCanonical = new C14nCanonicalization().process(payloadNode);
  const browserCanonical = new XmlCanonicalizer(false, false).Canonicalize(payloadNode);
  assert.equal(browserCanonical, nodeCanonical);
  assert.equal(parseLicense(xml).canonicalPayload, nodeCanonical);
});

test('the shared serializer produces the exact bytes issueLicense signs', () => {
  const xml = issueLicense(subscription, { keyId: 'test-key', privateKey });
  assert.ok(xml.includes(serializePayload(subscription)));
});

test('the shared parser accepts every license the library issues', () => {
  const licenses = [
    subscription,
    { ...subscription, type: 'perpetual', validity: { issuedAt: '2026-09-24T08:00:00Z' } },
    { ...subscription, type: 'trial' },
    { ...subscription, machine: { type: 'fingerprint', value: 'a'.repeat(64) } },
    { ...subscription, customer: { ...subscription.customer, email: 'licenses@example.com' } },
    { ...subscription, features: [], limits: [] },
  ];
  for (const payload of licenses) {
    const xml = issueLicense(payload, { keyId: 'test-key', privateKey });
    const shared = parseLicenseDocument(xml);
    const library = parseLicense(xml);
    assert.deepEqual(shared.payload, library.payload, JSON.stringify(payload));
    assert.equal(shared.keyId, library.keyId);
    assert.equal(shared.algorithm, library.algorithm);
    assert.deepEqual([...shared.signature], [...library.signature]);
  }
});

test('the shared parser enforces the protocol rules the browser playground relies on', () => {
  const invalid = [
    '<license version="1"></license>',
    '<other version="1"><payload/><signature algorithm="Ed25519" keyId="k">x</signature></other>',
    '<license version="2"><payload/><signature algorithm="Ed25519" keyId="k">x</signature></license>',
  ];
  for (const xml of invalid) {
    assert.throws(() => parseLicenseDocument(xml), xml);
    assert.equal(verifyLicense(xml, { publicKeys, now }).status, LicenseStatus.INVALID_FORMAT);
  }
});

test('perpetual licenses reject an expiresAt in the shared parser and the library', () => {
  const perpetualWithExpiry = { ...subscription, type: 'perpetual' };
  assert.throws(() => serializePayload(perpetualWithExpiry), /perpetual licenses must omit expiresAt/);
  assert.throws(() => issueLicense(perpetualWithExpiry, { keyId: 'test-key', privateKey }), /perpetual licenses must omit expiresAt/);
});

test('trial and subscription licenses require an expiresAt in the shared parser and the library', () => {
  for (const type of ['trial', 'subscription']) {
    const withoutExpiry = { ...subscription, type, validity: { issuedAt: '2026-09-24T08:00:00Z' } };
    assert.throws(() => serializePayload(withoutExpiry), new RegExp(`${type} licenses require expiresAt`));
    assert.throws(() => issueLicense(withoutExpiry, { keyId: 'test-key', privateKey }), new RegExp(`${type} licenses require expiresAt`));
  }
});

test('a hand-built perpetual license carrying an expiresAt is rejected as invalid format', () => {
  const payloadXml = [
    '<payload>',
    '  <licenseId>LIC-001</licenseId>',
    '  <product>',
    '    <id>example</id>',
    '    <version>5</version>',
    '  </product>',
    '  <type>perpetual</type>',
    '  <customer>',
    '    <id>customer-1</id>',
    '    <name>Acme Corporation</name>',
    '  </customer>',
    '  <validity>',
    '    <issuedAt>2026-09-24T08:00:00Z</issuedAt>',
    '    <expiresAt>2027-09-24T08:00:00Z</expiresAt>',
    '  </validity>',
    '  <features>',
    '  </features>',
    '  <limits>',
    '  </limits>',
    '  <machine>',
    '    <type>none</type>',
    '  </machine>',
    '</payload>',
  ].join('\n');
  const xml = ['<?xml version="1.0" encoding="UTF-8"?>', '<license version="1">', payloadXml, `  <signature algorithm="Ed25519" keyId="test-key">${'A'.repeat(88)}</signature>`, '</license>', ''].join('\n');
  assert.throws(() => parseLicenseDocument(xml), /perpetual licenses must omit expiresAt/);
  assert.equal(verifyLicense(xml, { publicKeys, now }).status, LicenseStatus.INVALID_FORMAT);
});

test('the DOM parser is hardened against DTDs, entities, and oversized input', () => {
  assert.throws(() => parseDocument('<!DOCTYPE license [<!ENTITY x "x">]><license/>'), /DTD and entity declarations are forbidden/);
  assert.throws(() => parseDocument('<license/>'.padEnd(1024 * 1024 + 1, ' ')), /exceeds the 1 MiB limit/);
  assert.throws(() => parseDocument('<license><unclosed></license>'));
  assert.throws(() => parseDocument('<license>'));
});

test('rejects stray content around the license root', () => {
  const xml = issueLicense(subscription, { keyId: 'test-key', privateKey });
  assert.throws(() => parseLicenseDocument(`<?custom data?>${xml.replace(/^<\?xml[^?]*\?>\n/, '')}`), /unexpected content outside license root/);
  assert.doesNotThrow(() => parseLicenseDocument(xml.replace('</license>', '</license><!-- trailing comment -->')));
});

test('rejects elements and text inside leaf and signature nodes', () => {
  const xml = issueLicense(subscription, { keyId: 'test-key', privateKey });
  assert.throws(() => parseLicenseDocument(xml.replace('<licenseId>LIC-001</licenseId>', '<licenseId><x/></licenseId>')), /licenseId must contain text only/);
  assert.throws(() => parseLicenseDocument(xml.replace(/<signature[^>]*>/, '$&<x/>')), /signature must contain text only/);
});

test('rejects payload values that carry XML-illegal code points', () => {
  assert.throws(() => serializePayload({ ...subscription, licenseId: '\u0001' }), /must be valid XML text/);
  assert.throws(() => serializePayload({ ...subscription, customer: { ...subscription.customer, name: '\uD800' } }), /must be valid XML text/);
});
