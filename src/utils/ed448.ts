/**
 * Ed448 signature verification for CorePass enrichment.
 * X-Signature is 114 bytes (228 hex chars or base64). Public key 57 bytes (114 hex or base64).
 */

function isHex(s: string): boolean {
	return /^[0-9a-fA-F]+$/.test(s);
}

function hexToBytes(hex: string): Uint8Array | null {
	if (!hex || hex.length % 2 !== 0) return null;
	if (!isHex(hex)) return null;
	const bytes = new Uint8Array(hex.length / 2);
	for (let i = 0; i < hex.length; i += 2) {
		bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
	}
	return bytes;
}

function tryBase64(s: string): Uint8Array | null {
	try {
		const binary = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
		const bytes = new Uint8Array(binary.length);
		for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
		return bytes;
	} catch {
		return null;
	}
}

export function parseEd448Signature(signature: string): Uint8Array | null {
	if (typeof signature !== 'string') return null;
	const s = signature.trim();
	if (!s) return null;
	if (isHex(s)) return hexToBytes(s);
	return tryBase64(s);
}

/** 57-byte Ed448 public key from 114 hex chars or base64. */
export function parseEd448PublicKey(value: string): Uint8Array | null {
	if (typeof value !== 'string') return null;
	const s = value.trim();
	if (!s) return null;
	const bytes = isHex(s) ? hexToBytes(s) : tryBase64(s);
	return bytes && bytes.length === 57 ? bytes : null;
}

/**
 * Derive Ed448 public key from long-form Core ID (BBAN = 114 hex chars = 57 bytes).
 * Short-form (40 hex) cannot be derived; use X-Public-Key header instead.
 */
export function publicKeyFromCoreIdLongForm(coreId: string): Uint8Array | null {
	if (typeof coreId !== 'string') return null;
	const s = coreId.trim();
	if (s.length < 4) return null;
	const bban = s.slice(4);
	if (bban.length !== 114 || !isHex(bban)) return null;
	return hexToBytes(bban);
}

export async function verifyEd448(args: {
	publicKeyBytes: Uint8Array;
	messageBytes: Uint8Array;
	signatureBytes: Uint8Array;
}): Promise<boolean> {
	const { publicKeyBytes, messageBytes, signatureBytes } = args;
	if (publicKeyBytes.length !== 57 || signatureBytes.length !== 114) return false;
	try {
		const { ed448 } = await import('@noble/curves/ed448.js');
		return ed448.verify(signatureBytes, messageBytes, publicKeyBytes);
	} catch {
		return false;
	}
}
