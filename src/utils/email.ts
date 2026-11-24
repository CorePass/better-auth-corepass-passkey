/**
 * Email format validation (regex). Used for enrichment payload, registration email, and requireAtLeastOneEmail.
 */

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_EMAIL_LENGTH = 254;

/**
 * Placeholders the Better Auth anonymous plugin generates:
 * - `<id>@anonymous.placeholder.invalid`, the default since better-auth 1.7;
 * - `temp-<id>@<emailDomainName>`, with a custom domain;
 * - `temp@<id>.com`, from older versions.
 */
const ANON_TEMP_EMAIL_REGEX = /^temp[-@]/i;
/** RFC 6761 reserves `.invalid`: an address there can never receive mail, so no user supplied it. */
const RESERVED_INVALID_DOMAIN_REGEX = /@(?:[^@\s]+\.)?invalid$/i;

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
 * Better Auth anonymous plugin (e.g. `abc@anonymous.placeholder.invalid`,
 * `temp-xyz@example.com`, `temp@abc.com`), or any address under `.invalid`.
 * These are syntactically valid but are not a real user-supplied address, so
 * `requireAtLeastOneEmail` must not accept them, and an account carrying one
 * counts as an unfinished registration.
 */
export function isAnonymousPlaceholderEmail(value: string | null | undefined): boolean {
	if (value == null || typeof value !== 'string') return false;
	const email = value.trim();
	return ANON_TEMP_EMAIL_REGEX.test(email) || RESERVED_INVALID_DOMAIN_REGEX.test(email);
}

/**
 * Returns true when the string is a valid email AND not an auto-generated
 * anonymous-plugin placeholder. Use this wherever a real user email is required.
 */
export function isRealUserEmail(value: string | null | undefined): boolean {
	return isValidEmail(value) && !isAnonymousPlaceholderEmail(value);
}
