/**
 * CorePass enrichment payload (POST /passkey/data).
 * @see authjs-corepass-provider README
 */

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
	/** Finalize: 'immediate' = user active right away; 'after' = on hold until POST /passkey/data. Default 'after'. */
	finalize?: 'immediate' | 'after';
	/** Path used for signature verification. Default /passkey/data. */
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
};
