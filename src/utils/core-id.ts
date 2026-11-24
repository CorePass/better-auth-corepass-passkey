/**
 * Binding an Ed448 public key to the Core ID a request claims.
 *
 * A valid signature only proves the caller holds the private key for the public key that
 * came with the request (`X-Public-Key`). It proves the claimed Core ID only once the
 * address derived from that key equals it; otherwise anyone could sign with their own key
 * and claim someone else's Core ID.
 *
 * Address derivation mirrors core-web3dart `publicKeyToAddress` (and CorePort's
 * `publicKeyToCoreId`): network prefix + ICAN checksum + last 20 bytes of sha3_256(publicKey).
 */
import { sha3_256 } from '@noble/hashes/sha3.js';

const PUBLIC_KEY_LENGTH = 57;
/** Core networks: mainnet, Devin testnet, enterprise. */
const NETWORK_PREFIXES = new Set(['cb', 'ab', 'ce']);

function bytesToHex(bytes: Uint8Array): string {
	let out = '';
	for (const b of bytes) out += b.toString(16).padStart(2, '0');
	return out;
}

/** ICAN check digits for `<prefix><checksum><bban>` (ISO 7064 MOD 97-10). */
function icanChecksum(bbanHex: string, prefix: string): string {
	const rearranged = `${bbanHex}${prefix}00`.toUpperCase();
	let digits = '';
	for (const ch of rearranged) {
		const code = ch.charCodeAt(0);
		digits += code >= 65 && code <= 90 ? String(code - 55) : ch;
	}
	return (98n - (BigInt(digits) % 97n)).toString().padStart(2, '0');
}

/** The (lowercase, short-form) Core ID of an Ed448 public key on a network. */
export function publicKeyToCoreId(publicKey: Uint8Array, prefix: string): string {
	if (publicKey.length !== PUBLIC_KEY_LENGTH) throw new Error('Ed448 public key must be 57 bytes');
	const bban = bytesToHex(sha3_256(publicKey).slice(12));
	return `${prefix}${icanChecksum(bban, prefix)}${bban}`;
}

/**
 * True when `coreId` belongs to `publicKey`:
 * - short form (prefix + checksum + 40 hex): the address derived from the key, checksum included;
 * - long form (prefix + checksum + 114 hex): the key itself is the BBAN.
 * Case and spacing don't matter. Anything else is false.
 */
export function coreIdMatchesPublicKey(coreId: string, publicKey: Uint8Array): boolean {
	if (typeof coreId !== 'string' || publicKey.length !== PUBLIC_KEY_LENGTH) return false;
	const id = coreId.replace(/\s+/g, '').toLowerCase();
	const prefix = id.slice(0, 2);
	if (!NETWORK_PREFIXES.has(prefix) || !/^[0-9]{2}[0-9a-f]+$/.test(id.slice(2))) return false;
	const bban = id.slice(4);
	if (bban.length === 40) return publicKeyToCoreId(publicKey, prefix) === id;
	if (bban.length === 114) return bban === bytesToHex(publicKey);
	return false;
}

/**
 * Enforces {@link coreIdMatchesPublicKey} for a signed CorePass request. Returns normally when
 * the key belongs to the Core ID, or when `mode` is `'log'` (after logging); throws otherwise.
 */
export function assertPublicKeyOwnsCoreId(args: {
	coreId: string;
	publicKey: Uint8Array;
	mode: 'reject' | 'log' | undefined;
	route: string;
	logger?: { warn?: (message: string, ...args: unknown[]) => void };
	reject: () => never;
}): void {
	if (coreIdMatchesPublicKey(args.coreId, args.publicKey)) return;
	args.logger?.warn?.(`[corepass ${args.route}] X-Public-Key does not belong to the claimed Core ID`, {
		coreId: args.coreId,
		mode: args.mode ?? 'reject'
	});
	if (args.mode === 'log') return;
	args.reject();
}
