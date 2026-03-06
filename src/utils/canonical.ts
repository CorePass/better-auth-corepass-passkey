/**
 * Canonical JSON for CorePass signature verification.
 * Recursively sort object keys and serialize with JSON.stringify (minified).
 * @see authjs-corepass-provider README: signatureInput = "POST\n" + signaturePath + "\n" + canonicalJsonBody
 */

function sortKeysRecursive(value: unknown): unknown {
	if (value === null || typeof value !== 'object') return value;
	if (Array.isArray(value)) return value.map(sortKeysRecursive);
	const obj = value as Record<string, unknown>;
	const out: Record<string, unknown> = {};
	for (const key of Object.keys(obj).sort()) {
		out[key] = sortKeysRecursive(obj[key]);
	}
	return out;
}

export function canonicalizeJSON(value: unknown): string {
	return JSON.stringify(sortKeysRecursive(value));
}

export function buildSignatureInput(method: string, path: string, canonicalBody: string): string {
	return `${method}\n${path}\n${canonicalBody}`;
}
