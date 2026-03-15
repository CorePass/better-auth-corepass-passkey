/**
 * CorePass enrichment payload (POST /webauthn/data).
 * @see authjs-corepass-provider README
 */

/** CorePass profile attached to user when present and not expired (get-session response). */
export type CorePassProfile = {
	coreId: string;
	o18y: boolean;
	o21y: boolean;
	kyc: boolean;
	kycDoc?: string;
	/** CorePass app backed up (passphrase), not passkey credential backup. */
	backedUp?: boolean;
	providedTill?: number;
};

export type EnrichmentUserData = {
	email?: string;
	o18y?: boolean | number;
	o21y?: boolean | number;
	kyc?: boolean | number;
	kycDoc?: string;
	dataExp?: number;
	/** Whether the user has backed up CorePass (not the passkey). When allowOnlyBackedUp is true, must be present and true. */
	backedUp?: boolean;
};

export type EnrichmentBody = {
	coreId: string;
	credentialId: string;
	timestamp: number;
	userData?: EnrichmentUserData;
};

export type CorePassPluginOptions = {
	/** Require email in enrichment payload (userData.email) only. Default false. All emails validated by regex. */
	requireEmail?: boolean;
	/** Require email from registration: request body of POST /sign-in/anonymous (e.g. signIn.anonymous({ email })). Validated before account creation; if missing or invalid, request is rejected. Default false. */
	requireRegistrationEmail?: boolean;
	/** Require at least one email: from registration (form) or enrichment. Enrichment overwrites when provided. All emails validated by regex. Default false. */
	requireAtLeastOneEmail?: boolean;
	/** Finalize: 'immediate' = user active right away; 'after' = on hold until POST /webauthn/data. Default 'after'. */
	finalize?: 'immediate' | 'after';
	/** Path used for signature verification. Default /webauthn/data. */
	signaturePath?: string;
	/** Timestamp window (ms). Default 600000. */
	timestampWindowMs?: number;
	/** Reject enrichment if userData.o18y !== true. */
	requireO18y?: boolean;
	/** Reject enrichment if userData.o21y !== true. */
	requireO21y?: boolean;
	/** Reject enrichment if userData.kyc !== true. */
	requireKyc?: boolean;
	/**
	 * Which Core (ICAN) networks to allow in enrichment. Default `['mainnet', 'enterprise']`.
	 * Array of 'mainnet' | 'testnet' | 'enterprise', or `true` (= mainnet only), or `false` (= testnet only).
	 */
	allowNetwork?: readonly ('mainnet' | 'testnet' | 'enterprise')[] | true | false;
	/** When true, require userData.backedUp to be present and true in enrichment (CorePass backed up). Default false. */
	allowOnlyBackedUp?: boolean;
	/**
	 * COSE algorithm IDs for passkey registration (pubKeyCredParams). When set, the plugin rewrites registration options to use these so more authenticators are supported.
	 * Ordered by strongest cryptography first; authenticators often pick the first they support.
	 * Default list (set to false to leave @better-auth/passkey defaults unchanged):
	 * -53 Ed448 (EdDSA, strongest), -19 Ed25519 (EdDSA), -8 EdDSA (generic),
	 * -36 ES512 (ECDSA/SHA-512), -7 ES256 (ECDSA/SHA-256),
	 * -39 RSASSA-PSS/SHA-512, -38 RSASSA-PSS/SHA-384, -37 RSASSA-PSS/SHA-256,
	 * -259 RSASSA-PKCS1-v1_5/SHA-512, -258 RSASSA-PKCS1-v1_5/SHA-384, -257 RSASSA-PKCS1-v1_5/SHA-256.
	 * Excluded: -65535 (RSA-PKCS1-v1_5/SHA-1, deprecated).
	 */
	supportedAlgorithmIDs?: number[] | false;
	/**
	 * AAGUID allowlist for passkey registration. Only these authenticator AAGUIDs are accepted.
	 * Default: Core Pass AAGUID `636f7265-7061-7373-6964-656e74696679`. Use string (one), string[] (many), or false to allow any.
	 * Applied via passkey create.before database hook.
	 */
	allowedAaguids?: string | string[] | false;
	/**
	 * Paths that remain accessible when user has no passkey yet. Default [] — only public behaviour applies:
	 * safe methods (GET, HEAD, OPTIONS) and passkey registration routes. Add paths only if you need extra routes.
	 */
	allowRoutesBeforePasskey?: string[];
	/**
	 * HTTP methods that are always allowed before first passkey (e.g. GET for session, OPTIONS for CORS).
	 * Default ['GET', 'HEAD', 'OPTIONS'].
	 */
	allowMethodsBeforePasskey?: string[];
	/**
	 * Paths used by Better Auth passkey plugin for registration; only needed if you use custom paths.
	 * Default already includes `/passkey/generate-register-options` and `/passkey/verify-registration`.
	 */
	allowPasskeyRegistrationRoutes?: string[];
	/**
	 * Accounts that still have no passkey after this many ms since creation are deleted on next request.
	 * Default 300_000 (5 minutes). Set to 0 to disable.
	 */
	deleteAccountWithoutPasskeyAfterMs?: number;
	/**
	 * Path used for restore signature verification. Default `/webauthn/restore`.
	 * Must match what CorePass uses when signing the restore payload.
	 */
	restoreSignaturePath?: string;
	/**
	 * How long a restore challenge is valid (ms). Default 300_000 (5 minutes).
	 */
	restoreChallengeExpiryMs?: number;
};
