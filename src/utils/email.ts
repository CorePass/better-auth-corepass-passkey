/**
 * Email format validation (regex). Used for enrichment payload, registration email, and requireAtLeastOneEmail.
 */

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_EMAIL_LENGTH = 254;

/** Matches placeholders the Better Auth anonymous plugin generates: `temp@<id>.com` or `temp-<id>@<domain>`. */
const ANON_TEMP_EMAIL_REGEX = /^temp[-@]/i;

/**
 * Returns true if the string is a non-empty, valid email format.
 */
export function isValidEmail(value: string | null | undefined): boolean {
	if (value == null || typeof value !== 'string') return false;
	const trimmed = value.trim();
	return trimmed.length > 0 && trimmed.length <= MAX_EMAIL_LENGTH && EMAIL_REGEX.test(trimmed);
}

/**
 * Returns true if the value is an auto-generated placeholder email from the
 * Better Auth anonymous plugin (e.g. `temp@abc.com`, `temp-xyz@example.com`).
 * These are syntactically valid but are not a real user-supplied address, so
 * `requireAtLeastOneEmail` must not accept them.
 */
export function isAnonymousPlaceholderEmail(value: string | null | undefined): boolean {
	if (value == null || typeof value !== 'string') return false;
	return ANON_TEMP_EMAIL_REGEX.test(value.trim());
}

/**
 * Returns true when the string is a valid email AND not an auto-generated
 * anonymous-plugin placeholder. Use this wherever a real user email is required.
 */
export function isRealUserEmail(value: string | null | undefined): boolean {
	return isValidEmail(value) && !isAnonymousPlaceholderEmail(value);
}
