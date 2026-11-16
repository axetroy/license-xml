import { XmlCanonicalizer } from 'xmldsigjs';
import { parseDocument, parseLicenseDocument, serializePayload } from '../src/protocol.js';

const examplePayload = {
  licenseId: 'LIC-DEMO-001',
  product: { id: 'my-product', version: '5' },
  type: 'subscription',
  customer: { id: 'DEMO-CUSTOMER', name: '示例客户', email: 'demo@example.com' },
  validity: {
    issuedAt: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
  },
  features: [{ id: 'export', enabled: true }, { id: 'sso', enabled: false }],
  limits: [{ id: 'users', value: '50' }],
  machine: { type: 'none' },
};

const encoder = new TextEncoder();
const english = new URLSearchParams(location.search).get('lang') === 'en';
const payloadField = document.querySelector('#payload');
const publicKeyField = document.querySelector('#public-key');
const licenseField = document.querySelector('#license');
const resultField = document.querySelector('#result');
const signButton = document.querySelector('#sign');
const verifyButton = document.querySelector('#verify');
const copyButton = document.querySelector('#copy-key');
const fullscreenButton = document.querySelector('#fullscreen');
let demoPrivateKey;

payloadField.value = JSON.stringify(examplePayload, null, 2);

fullscreenButton.addEventListener('click', async () => {
  try {
    if (document.fullscreenElement) {
      await document.exitFullscreen();
    } else {
      await document.documentElement.requestFullscreen();
    }
  } catch {
    fullscreenButton.disabled = true;
  }
});

document.addEventListener('fullscreenchange', () => {
  const label = document.fullscreenElement ? '退出全屏' : '全屏';
  fullscreenButton.textContent = text(label);
  fullscreenButton.setAttribute('aria-label', text(label));
});

document.querySelector('#reset').addEventListener('click', () => {
  payloadField.value = JSON.stringify(examplePayload, null, 2);
  licenseField.value = '';
  demoPrivateKey = undefined;
  publicKeyField.value = '';
  copyButton.disabled = true;
  showResult(text('等待验证'), text('签名结果会显示在这里。'));
});

signButton.addEventListener('click', async () => {
  signButton.disabled = true;
  licenseField.value = '';
  publicKeyField.value = '';
  demoPrivateKey = undefined;
  copyButton.disabled = true;
  try {
    ensureEd25519();
    const payloadXml = serializePayload(JSON.parse(payloadField.value));
    const keyPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    demoPrivateKey = keyPair.privateKey;
    const publicDer = new Uint8Array(await crypto.subtle.exportKey('spki', keyPair.publicKey));
    publicKeyField.value = toPem(publicDer, 'PUBLIC KEY');
    copyButton.disabled = false;

    const payloadNode = parseDocument(payloadXml).documentElement;
    const signature = new Uint8Array(await crypto.subtle.sign('Ed25519', demoPrivateKey, encoder.encode(canonicalize(payloadNode))));
    licenseField.value = [
      '<?xml version="1.0" encoding="UTF-8"?>',
      '<license version="1">',
      payloadXml,
      `  <signature algorithm="Ed25519" keyId="playground-demo">${toBase64(signature)}</signature>`,
      '</license>',
      '',
    ].join('\n');
    showResult(text('许可证已签名'), text('演示密钥只存在于当前页面内存中；请验证后尝试篡改载荷。'), true);
  } catch (error) {
    showResult(text('无法签名'), errorMessage(error.message));
  } finally {
    signButton.disabled = false;
  }
});

verifyButton.addEventListener('click', async () => {
  verifyButton.disabled = true;
  try {
    ensureEd25519();
    const parsed = parseLicenseDocument(licenseField.value);
    const publicKey = await crypto.subtle.importKey('spki', fromPem(publicKeyField.value, 'PUBLIC KEY'), { name: 'Ed25519' }, false, ['verify']);
    const valid = await crypto.subtle.verify('Ed25519', publicKey, parsed.signature, encoder.encode(canonicalize(parsed.payloadNode)));
    if (!valid) {
      showResult(text('签名无效'), text('签名与载荷不匹配，许可证内容可能被修改。'));
      return;
    }

    validateValidity(parsed.payload);
    if (parsed.payload.machine.type === 'fingerprint') {
      throw new Error('机器绑定许可证需由集成应用提供实际机器指纹；本演示不采集设备信息。');
    }
    showResult(text('签名有效'), english
      ? `Signature verified. License ID: ${parsed.payload.licenseId}; product: ${parsed.payload.product.id}.`
      : `签名验证通过。许可证 ID：${parsed.payload.licenseId}，产品：${parsed.payload.product.id}。`, true);
  } catch (error) {
    showResult(text('验证失败'), errorMessage(error.message));
  } finally {
    verifyButton.disabled = false;
  }
});

copyButton.addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(publicKeyField.value);
    copyButton.textContent = text('已复制');
    setTimeout(() => { copyButton.textContent = text('复制'); }, 1500);
  } catch {
    publicKeyField.focus();
    publicKeyField.select();
  }
});

function ensureEd25519() {
  if (!globalThis.crypto?.subtle) throw new Error('当前环境不支持 Web Crypto，请使用 HTTPS 或 localhost 打开页面。');
}

const englishText = {
  '等待验证': 'Ready to verify',
  '签名结果会显示在这里。': 'Verification results will appear here.',
  '许可证已签名': 'License signed',
  '演示密钥只存在于当前页面内存中；请验证后尝试篡改载荷。': 'The demo key exists only in this page memory. Verify the license, then try changing its payload.',
  '无法签名': 'Unable to sign',
  '签名无效': 'Invalid signature',
  '签名与载荷不匹配，许可证内容可能被修改。': 'The signature does not match the payload. The license may have been modified.',
  '签名有效': 'Signature valid',
  '验证失败': 'Verification failed',
  '已复制': 'Copied',
  '复制': 'Copy',
  '全屏': 'Fullscreen',
  '退出全屏': 'Exit fullscreen',
  '当前环境不支持 Web Crypto，请使用 HTTPS 或 localhost 打开页面。': 'Web Crypto is unavailable. Open this page over HTTPS or localhost.',
  '机器绑定许可证需由集成应用提供实际机器指纹；本演示不采集设备信息。': 'Machine-bound licenses require a fingerprint from the integrating application; this demo does not collect device information.',
  '许可证尚未生效（NOT_YET_VALID）。': 'License is not yet valid (NOT_YET_VALID).',
  '许可证已过期（EXPIRED）。': 'License has expired (EXPIRED).',
};

const protocolMessages = {
  'license XML must be a string': '许可证 XML 必须是字符串。',
  'license XML exceeds the 1 MiB limit': '许可证 XML 超过 1 MiB 限制。',
  'DTD and entity declarations are forbidden': '禁止 DTD 和实体声明。',
  'XML declaration must specify version 1.0': 'XML 声明必须指定版本 1.0。',
  'XML declaration encoding must be UTF-8': 'XML 声明编码必须为 UTF-8。',
  'DOCTYPE is forbidden': '禁止 DOCTYPE。',
  'missing document element': '缺少文档根元素。',
  'malformed XML': 'XML 格式错误。',
  'root element must be unnamespaced <license>': '根元素必须是无命名空间的 <license>。',
  'unsupported protocol version': '不支持的协议版本。',
  'unexpected content outside license root': 'license 根元素之外存在意外内容。',
  'invalid license structure': 'license 结构不符合 License XML v1.0。',
  'payload must be unnamespaced': 'payload 必须无命名空间。',
  'invalid payload structure': 'payload 结构不符合 License XML v1.0。',
  'licenseId must be 1–128 UTF-8 bytes': 'licenseId 必须为 1–128 个 UTF-8 字节。',
  'product id must be 1–128 UTF-8 bytes': 'product id 必须为 1–128 个 UTF-8 字节。',
  'product version must be a non-negative decimal integer without leading zeros': 'product version 必须为不带前导零的非负十进制整数。',
  'invalid license type': '许可证类型无效。',
  'customer id and name are required': 'customer id 和 name 为必填项。',
  'expiresAt must be later than issuedAt': 'expiresAt 必须晚于 issuedAt。',
  'perpetual licenses must omit expiresAt': 'perpetual 许可证必须省略 expiresAt。',
  'trial licenses require expiresAt': 'trial 许可证必须提供 expiresAt。',
  'subscription licenses require expiresAt': 'subscription 许可证必须提供 expiresAt。',
  'features element is invalid': 'features 元素无效。',
  'features may contain only feature elements': 'features 只能包含 feature 元素。',
  'invalid feature id': 'feature id 无效。',
  'feature enabled must be true or false': 'feature enabled 必须为 true 或 false。',
  'feature element must be empty': 'feature 必须为空元素。',
  'limits element is invalid': 'limits 元素无效。',
  'limits may contain only limit elements': 'limits 只能包含 limit 元素。',
  'invalid limit id': 'limit id 无效。',
  'limit value must be a non-negative decimal integer without leading zeros': 'limit value 必须为不带前导零的非负十进制整数。',
  'invalid machine binding type': 'machine 绑定类型无效。',
  'machine value must be omitted when type is none': 'machine.type 为 none 时不得包含 value。',
  'machine value is required for fingerprint binding': 'fingerprint 绑定必须提供 machine value。',
  'machine fingerprint must be 64 hexadecimal characters': 'machine 指纹必须为 64 位十六进制字符。',
  'invalid signature keyId': 'signature keyId 无效。',
  'signature is not canonical Base64': '签名不是标准 Base64。',
  'invalid Ed25519 signature length or encoding': 'Ed25519 签名长度或编码无效。',
  'namespaces are forbidden': 'License XML v1.0 不允许 XML 命名空间。',
  'payload is missing a required object': '载荷缺少必需的对象。',
  'payload must be an object': '载荷必须是对象。',
  'features and limits must be arrays': 'features 和 limits 必须是数组。',
  'feature enabled must be a boolean': 'feature enabled 必须是布尔值。',
  'payload values are not in canonical protocol form': '载荷值不符合协议的规范形式。',
};

const protocolPatterns = [
  [/^unexpected text in (.+)$/, '$1 中存在意外文本。'],
  [/^unexpected XML node in (.+)$/, '$1 中存在不支持的 XML 内容。'],
  [/^(.+) must contain text only$/, '$1 只能包含文本。'],
  [/^invalid (.+)\/(.+) element count$/, '$1/$2 元素数量无效。'],
  [/^unexpected element in (.+)$/, '$1 中存在意外元素。'],
  [/^invalid (.+) structure$/, '$1 结构无效。'],
  [/^invalid (.+) attributes$/, '$1 属性无效。'],
  [/^(.+) element is invalid$/, '$1 元素无效。'],
  [/^(.+) must not be empty or have surrounding whitespace$/, '$1 不得为空或包含首尾空白。'],
  [/^(.+) must be valid XML text$/, '$1 必须是合法的 XML 文本。'],
  [/^unknown (.+) field$/, '$1 包含未知字段。'],
  [/^(.+) must be an object$/, '$1 必须是对象。'],
  [/^(.+) must use YYYY-MM-DDTHH:mm:ssZ$/, '$1 必须使用 YYYY-MM-DDTHH:mm:ssZ 格式。'],
  [/^(.+) is not a valid UTC calendar time$/, '$1 不是有效的 UTC 时间。'],
  [/^duplicate (.+) id$/, '$1 id 不得重复。'],
];

function text(chinese) {
  return english ? englishText[chinese] ?? chinese : chinese;
}

function errorMessage(message) {
  if (english) {
    if (englishText[message]) return englishText[message];
    return /[\u3400-\u9fff]/.test(message) ? 'The license input is invalid. Check its XML structure and format.' : message;
  }
  if (protocolMessages[message]) return protocolMessages[message];
  for (const [pattern, replacement] of protocolPatterns) {
    if (pattern.test(message)) return message.replace(pattern, replacement);
  }
  return message;
}

function localizeInterface() {
  document.documentElement.lang = 'en';
  document.title = 'License XML Playground';
  document.querySelector('.brand').setAttribute('aria-label', 'License XML Playground home');
  document.querySelector('.doc-link').textContent = 'Protocol specification ↗';
  fullscreenButton.textContent = text('全屏');
  fullscreenButton.setAttribute('aria-label', text('全屏'));
  document.querySelector('.eyebrow').lastChild.textContent = ' LICENSE XML · VERSION 1.0';
  document.querySelector('.intro h1').textContent = 'Explore license signing and verification.';
  document.querySelector('.intro-copy').textContent = 'Edit a license payload, sign it with a temporary Ed25519 key, then change it and verify the signature. Everything runs in this browser.';
  const warning = document.querySelector('.warning > div');
  const warningTitle = document.createElement('strong');
  warningTitle.textContent = 'For learning and demonstration only';
  warning.replaceChildren(warningTitle, document.createElement('br'), document.createTextNode('The private key is held only in this page memory and is lost when you reload. Never use a demo key for production issuance. This playground does not upload payloads or keys.'));
  document.querySelectorAll('.panel-heading h2')[0].textContent = 'License payload';
  document.querySelectorAll('.panel-heading h2')[1].textContent = 'Sign and verify';
  document.querySelectorAll('.panel-caption')[0].textContent = 'JSON · editable';
  document.querySelectorAll('.panel-caption')[1].textContent = 'XML · local processing';
  document.querySelector('label[for="payload"]').textContent = 'License payload';
  document.querySelector('#payload').setAttribute('aria-label', 'License payload JSON');
  document.querySelector('#sign').lastChild.textContent = ' Sign and issue';
  document.querySelector('#reset').textContent = 'Reset example';
  document.querySelector('.key-card strong').textContent = 'Temporary demo public key';
  document.querySelector('#copy-key').textContent = 'Copy';
  document.querySelector('#public-key').setAttribute('aria-label', 'Verification public key');
  document.querySelector('#public-key').placeholder = 'Generated after signing, or paste an existing SPKI PEM public key';
  document.querySelector('.hint').textContent = 'A temporary key is generated in this browser. Only signatures matching this public key will verify.';
  document.querySelector('label[for="license"]').textContent = 'Signed license';
  document.querySelector('#license').setAttribute('aria-label', 'Signed license XML');
  document.querySelector('#license').placeholder = 'Signed License XML appears here, or paste an existing license';
  document.querySelector('#verify').firstChild.textContent = 'Verify license ';
  document.querySelector('.verify-caption').textContent = 'Checks signature and validity; machine binding requires an integrated fingerprint';
  document.querySelector('#result strong').textContent = text('等待验证');
  document.querySelector('#result p').textContent = text('签名结果会显示在这里。');
  document.querySelector('footer > span').textContent = 'License XML v1.0 · Ed25519 · Canonical XML 1.0';
  document.querySelector('footer > span:last-child').firstChild.textContent = 'Keys stay in your browser ';
}

if (english) localizeInterface();

function validateValidity(payload) {
  const now = Date.now();
  if (now < Date.parse(payload.validity.issuedAt)) throw new Error('许可证尚未生效（NOT_YET_VALID）。');
  if (payload.validity.expiresAt && now >= Date.parse(payload.validity.expiresAt)) throw new Error('许可证已过期（EXPIRED）。');
}

function canonicalize(node) {
  return new XmlCanonicalizer(false, false).Canonicalize(node);
}

function toBase64(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(value) {
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new Error('签名必须是标准 Base64。');
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}

function toPem(bytes, label) {
  const base64 = toBase64(bytes).match(/.{1,64}/g).join('\n');
  return `-----BEGIN ${label}-----\n${base64}\n-----END ${label}-----`;
}

function fromPem(pem, label) {
  const match = new RegExp(`^-----BEGIN ${label}-----\\s+([A-Za-z0-9+/=\\s]+)\\s+-----END ${label}-----$`).exec(pem.trim());
  if (!match) throw new Error('公钥必须是有效的 SPKI PEM 格式。');
  return fromBase64(match[1].replace(/\s/g, ''));
}

function showResult(title, message, success = false) {
  resultField.className = `result ${success ? 'result-success' : 'result-error'}`;
  resultField.replaceChildren();
  const indicator = document.createElement('span');
  indicator.className = 'result-indicator';
  const content = document.createElement('div');
  const heading = document.createElement('strong');
  heading.textContent = title;
  const description = document.createElement('p');
  description.textContent = message;
  content.append(heading, description);
  resultField.append(indicator, content);
}
