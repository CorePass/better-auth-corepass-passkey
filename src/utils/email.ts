/**
 * Email format validation (regex). Used for enrichment payload, registration email, and requireAtLeastOneEmail.
 */

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_EMAIL_LENGTH = 254;

/**
 * Returns true if the string is a non-empty, valid email format.
 */
export function isValidEmail(value: string | null | undefined): boolean {
	if (value == null || typeof value !== 'string') return false;
	const trimmed = value.trim();
	return trimmed.length > 0 && trimmed.length <= MAX_EMAIL_LENGTH && EMAIL_REGEX.test(trimmed);
}
