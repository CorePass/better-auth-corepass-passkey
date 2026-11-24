/**
 * Test helper: a CorePass identity whose Core ID really belongs to its Ed448 key.
 *
 * Re-implements the address derivation (prefix + ICAN checksum + last 20 bytes of
 * sha3_256(publicKey)) rather than importing the plugin's, so the tests check the plugin
 * against an independent copy of the rule.
 */
import { ed448 } from '@noble/curves/ed448.js';
import { sha3_256 } from '@noble/hashes/sha3.js';

const hex = (b) => Buffer.from(b).toString('hex');

function icanChecksum(bban, prefix) {
	const digits = [...`${bban}${prefix}00`.toUpperCase()]
		.map((ch) => (ch >= 'A' && ch <= 'Z' ? String(ch.charCodeAt(0) - 55) : ch))
		.join('');
	return (98n - (BigInt(digits) % 97n)).toString().padStart(2, '0');
}

export function coreIdForPublicKey(publicKey, prefix = 'cb') {
	const bban = hex(sha3_256(publicKey).slice(12));
	return `${prefix}${icanChecksum(bban, prefix)}${bban}`;
}

/** A fresh key pair and its Core ID (uppercase, as enrichment stores it). */
export function newCorePassKey(prefix = 'cb') {
	const priv = ed448.utils.randomSecretKey ? ed448.utils.randomSecretKey() : ed448.utils.randomPrivateKey();
	const pub = ed448.getPublicKey(priv);
	return { priv, pub, coreId: coreIdForPublicKey(pub, prefix).toUpperCase() };
}

/** Signs `POST\n<path>\n<canonical>` the way CorePass does; returns the request headers. */
export function signedHeaders(key, path, canonical) {
	const sig = ed448.sign(new TextEncoder().encode(`POST\n${path}\n${canonical}`), key.priv);
	return {
		'Content-Type': 'application/json',
		Origin: 'http://localhost',
		'X-Signature': hex(sig),
		'X-Public-Key': hex(key.pub)
	};
}
