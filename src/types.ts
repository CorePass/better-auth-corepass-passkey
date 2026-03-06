/**
 * CorePass enrichment payload (POST /webauthn/data).
 * @see authjs-corepass-provider README
 */

export type EnrichmentUserData = {
	email?: string;
	o18y?: boolean | number;
	o21y?: boolean | number;
	kyc?: boolean | number;
	kycDoc?: string;
	dataExp?: number;
};

export type EnrichmentBody = {
	coreId: string;
	credentialId: string;
	timestamp: number;
	userData?: EnrichmentUserData;
};

export type CorePassPluginOptions = {
	/** When true, require email when registering; enrichment POST is rejected if userData.email is missing or empty. */
	requireEmail?: boolean;
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
	 * AAGUID allowlist for passkey registration. When set, only these authenticator AAGUIDs are accepted.
	 * Use false or omit to allow any. Applied via passkey create.before database hook.
	 */
	allowedAaguids?: string | string[] | false;
};
