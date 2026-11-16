export type LicenseType = 'trial' | 'subscription' | 'perpetual';
export type MachineType = 'none' | 'fingerprint';

export interface Product {
  id: string;
  version: string | number;
}

export interface Customer {
  id: string;
  name: string;
  email?: string;
}

export interface Validity {
  issuedAt: string;
  expiresAt?: string;
}

export interface Feature {
  id: string;
  enabled: boolean;
}

export interface Limit {
  id: string;
  value: string | number;
}

export interface MachineBinding {
  type: MachineType;
  value?: string;
}

/** Input accepted by {@link issueLicense}. Values are normalized to strings in the signed license. */
export interface LicensePayload {
  licenseId: string;
  product: Product;
  type: LicenseType;
  customer: Customer;
  validity: Validity;
  features: Feature[];
  limits: Limit[];
  machine: MachineBinding;
}

/** The canonical payload parsed out of a signed license, with numeric values normalized to strings. */
export interface License {
  licenseId: string;
  product: { id: string; version: string };
  type: LicenseType;
  customer: { id: string; name: string; email?: string };
  validity: { issuedAt: string; expiresAt?: string };
  features: Feature[];
  limits: Array<{ id: string; value: string }>;
  machine: { type: MachineType; value?: string };
}

export declare const LicenseStatus: {
  readonly VALID: 'VALID';
  readonly INVALID_FORMAT: 'INVALID_FORMAT';
  readonly INVALID_SIGNATURE: 'INVALID_SIGNATURE';
  readonly PRODUCT_MISMATCH: 'PRODUCT_MISMATCH';
  readonly NOT_YET_VALID: 'NOT_YET_VALID';
  readonly EXPIRED: 'EXPIRED';
  readonly MACHINE_MISMATCH: 'MACHINE_MISMATCH';
};

export type LicenseStatus = (typeof LicenseStatus)[keyof typeof LicenseStatus];

export interface IssueOptions {
  keyId: string;
  privateKey: string | Uint8Array;
}

export interface ParsedLicense {
  payload: License;
  algorithm: string;
  keyId: string;
  signature: Uint8Array;
  canonicalPayload: string;
}

export interface VerifyOptions {
  /** A `Map` or plain object mapping key IDs to SPKI PEM public keys. */
  publicKeys?: Map<string, string | Uint8Array> | Record<string, string | Uint8Array> | null;
  productId?: string;
  productVersion?: string | number;
  machineFingerprint?: string;
  now?: Date | string | number;
}

export interface VerifyResult {
  status: LicenseStatus;
  license?: License;
}

export declare function generateKeyPair(): { privateKey: string; publicKey: string };

export declare function issueLicense(payload: LicensePayload, options: IssueOptions): string;

export declare function parseLicense(xml: string): ParsedLicense;

export declare function verifyLicense(xml: string, options?: VerifyOptions | null): VerifyResult;
