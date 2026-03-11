/**
 * Better Auth plugin: CorePass enrichment for passkey.
 * Adds POST /passkey/data for signed enrichment payload, corepass_profile schema, requireO18y/requireO21y/requireKyc.
 * Optional allowedAaguids: passkey create.before hook to allow only listed AAGUIDs.
 * Users without a passkey are blocked from auth endpoints except public behaviour (safe methods + passkey registration).
 * Must be used after @better-auth/passkey.
 */

import type { AuthContext } from 'better-auth';
import { APIError, createAuthMiddleware, getSessionFromCtx } from 'better-auth/api';
import {
	createEnrichmentEndpoint,
	createGetEnrichmentEndpoint,
	createHeadEnrichmentEndpoint
} from './enrichment-handler.js';
import type { CorePassPluginOptions } from './types.js';
import { hasAnyPasskey, isAllowedBeforePasskey } from './utils/passkey-state.js';
import { isValidEmail } from './utils/email.js';

function normalizeAaguid(value: string): string {
	return String(value).toLowerCase().replace(/\s+/g, '').trim();
}

function isAaguidAllowed(aaguid: string | undefined | null, allowlist: string | string[]): boolean {
	if (aaguid == null || aaguid === '') return false;
	const normalized = normalizeAaguid(aaguid);
	const list = Array.isArray(allowlist) ? allowlist : [allowlist];
	const set = new Set(list.map(normalizeAaguid));
	return set.has(normalized);
}

export const corepassPasskeySchema = {
	corepass_profile: {
		fields: {
			userId: {
				type: 'string' as const,
				required: true as const,
				references: { model: 'user', field: 'id' },
				index: true as const
			},
			coreId: {
				type: 'string' as const,
				required: true as const
			},
			o18y: {
				type: 'number' as const,
				required: true as const
			},
			o21y: {
				type: 'number' as const,
				required: true as const
			},
			kyc: {
				type: 'number' as const,
				required: true as const
			},
			kycDoc: {
				type: 'string' as const,
				required: false as const
			},
			providedTill: {
				type: 'number' as const,
				required: false as const
			}
		}
	}
};

const PASSKEY_REQUIRED_ERROR = {
	message: 'A passkey is required to access this resource. Complete passkey registration first.',
	code: 'PASSKEY_REQUIRED' as const
};

const REGISTRATION_TIMEOUT_ERROR = {
	message: 'Registration timed out. Add a passkey within the allowed time, or start again.',
	code: 'REGISTRATION_TIMEOUT' as const
};

const EMAIL_REQUIRED_ERROR = {
	message: 'Email is required from registration or enrichment.',
	code: 'EMAIL_REQUIRED' as const
};

const CORE_ID_INVALID_ERROR = {
	message: 'Core ID (ICAN) is invalid.',
	code: 'CORE_ID_INVALID' as const
};

const CORE_ID_NETWORK_NOT_ALLOWED_ERROR = {
	message: 'Core ID network (mainnet/testnet/enterprise) is not allowed.',
	code: 'CORE_ID_NETWORK_NOT_ALLOWED' as const
};

const BACKED_UP_REQUIRED_ERROR = {
	message: 'CorePass must be backed up.',
	code: 'BACKED_UP_REQUIRED' as const
};

/** Only anonymous registration can be restarted: POST /sign-in/anonymous. Sign-in (email, OAuth) is not reset; user must wait for expiration and retry. */
const RESTART_REGISTRATION_PATH = '/sign-in/anonymous';

/** Default AAGUID for Core Pass authenticator. Use allowedAaguids: false to allow any. */
const DEFAULT_AAGUID = '636f7265-7061-7373-6964-656e74696679';

/**
 * Expanded COSE algorithm IDs for pubKeyCredParams, ordered by strongest cryptography first (authenticators often pick the first they support).
 * -53 Ed448, -19 Ed25519, -8 EdDSA (generic), -36 ES512, -7 ES256, -39..-37 RSA-PSS, -259..-257 RSA-PKCS1; excludes -65535 (SHA-1).
 */
const EXPANDED_SUPPORTED_ALGORITHM_IDS = [-53, -19, -8, -36, -7, -39, -38, -37, -259, -258, -257];

export function corepassPasskey(options: CorePassPluginOptions = {}) {
	const raw = options.allowedAaguids;
	const effectiveAllowlist: string | string[] | null =
		raw === false
			? null
			: raw === undefined
				? DEFAULT_AAGUID
				: Array.isArray(raw)
					? (raw.length === 0 ? null : raw)
					: raw;
	const hasAllowlist = effectiveAllowlist !== null;

	const deleteAfterMs = options.deleteAccountWithoutPasskeyAfterMs ?? 300_000;
	const gateOptions = {
		allowRoutesBeforePasskey: options.allowRoutesBeforePasskey,
		allowMethodsBeforePasskey: options.allowMethodsBeforePasskey,
		allowPasskeyRegistrationRoutes: options.allowPasskeyRegistrationRoutes
	};

	const beforeHook = {
		matcher: () => true,
		handler: createAuthMiddleware(async (ctx) => {
						const path = (ctx as { path?: string }).path ?? '/';
						const method = (ctx as { method?: string }).method ?? (ctx as { request?: { method?: string } }).request?.method ?? 'GET';
						const pathNorm = path.replace(/\/+$/, '') || '/';
						const session = await getSessionFromCtx(ctx, { disableRefresh: true });
						if (!session?.user?.id) {
							if (method.toUpperCase() === 'POST' && pathNorm === RESTART_REGISTRATION_PATH && options.requireRegistrationEmail) {
								const body = (ctx as { body?: { email?: string } }).body ?? {};
								const email = typeof body.email === 'string' ? body.email.trim() : '';
								if (!isValidEmail(email)) {
									throw new APIError('BAD_REQUEST', {
										message: 'requireRegistrationEmail: valid email is required in request body (e.g. signIn.anonymous({ email }))',
										code: 'EMAIL_REQUIRED'
									});
								}
							}
							return;
						}
						const adapter = ctx.context.adapter as { findOne: (arg: { model: string; where: { field: string; value: unknown }[] }) => Promise<unknown> };
						const hasPasskey = await hasAnyPasskey(adapter, session.user.id);
						if (hasPasskey) {
							const needEmail = options.requireRegistrationEmail || options.requireAtLeastOneEmail;
							const userEmail = (session.user as { email?: string | null }).email;
							if (needEmail && !isValidEmail(userEmail)) {
								const internal = ctx.context.internalAdapter as { deleteUser: (id: string) => Promise<unknown>; deleteSessions: (userId: string) => Promise<unknown> };
								try {
									await internal.deleteSessions(session.user.id);
									await internal.deleteUser(session.user.id);
								} catch (err) {
									ctx.context.logger?.error?.('Failed to clean account: email required', err);
								}
								throw new APIError('FORBIDDEN', EMAIL_REQUIRED_ERROR);
							}
							return;
						}
						if (method.toUpperCase() === 'POST' && pathNorm === RESTART_REGISTRATION_PATH) {
							const internal = ctx.context.internalAdapter as {
								deleteUser: (id: string) => Promise<unknown>;
								deleteSessions: (userId: string) => Promise<unknown>;
								deleteSession?: (token: string) => Promise<unknown>;
							};
							try {
								const token = (session.session as { token?: string })?.token;
								if (token && typeof internal.deleteSession === 'function') {
									await internal.deleteSession(token);
								}
								await internal.deleteSessions(session.user.id);
								await internal.deleteUser(session.user.id);
							} catch (err) {
								ctx.context.logger?.error?.('Failed to delete user for registration restart', err);
							}
							// Clear cached session so the anonymous plugin's handler does a fresh lookup and gets null, allowing a new anonymous sign-in.
							(ctx as { context: { session?: unknown } }).context.session = undefined;
							return;
						}
						if (isAllowedBeforePasskey(path, method, gateOptions)) {
							return;
						}
						if (deleteAfterMs > 0) {
							const userCreatedAt =
								(session.user as { createdAt?: Date }).createdAt ??
								((await adapter.findOne({ model: 'user', where: [{ field: 'id', value: session.user.id }] })) as { createdAt?: Date } | null)?.createdAt;
							const createdAtMs = userCreatedAt instanceof Date ? userCreatedAt.getTime() : userCreatedAt ? new Date(userCreatedAt).getTime() : 0;
							if (createdAtMs > 0 && Date.now() - createdAtMs >= deleteAfterMs) {
								const internal = ctx.context.internalAdapter as { deleteUser: (id: string) => Promise<unknown>; deleteSessions: (userId: string) => Promise<unknown> };
								try {
									await internal.deleteSessions(session.user.id);
									await internal.deleteUser(session.user.id);
								} catch (err) {
									ctx.context.logger?.error?.('Failed to delete account without passkey', err);
								}
								throw new APIError('FORBIDDEN', REGISTRATION_TIMEOUT_ERROR);
							}
						}
			throw new APIError('FORBIDDEN', PASSKEY_REQUIRED_ERROR);
		})
	};

	const afterHook = {
		matcher: () => true,
		handler: createAuthMiddleware(async (ctx) => {
			const path = (ctx as { path?: string }).path ?? '/';
			const method = (ctx as { method?: string }).method ?? (ctx as { request?: { method?: string } }).request?.method ?? 'GET';
			const pathNorm = path.replace(/\/+$/, '') || '/';
			if (method.toUpperCase() !== 'POST' || pathNorm !== RESTART_REGISTRATION_PATH) return;
			const session = await getSessionFromCtx(ctx, { disableRefresh: true });
			if (!session?.user?.id) return;
			const body = (ctx as { body?: { email?: string } }).body ?? {};
			const email = typeof body.email === 'string' ? body.email.trim() : '';
			if (!isValidEmail(email)) return;
			const adapter = ctx.context.adapter as {
				update: (arg: { model: string; where: { field: string; value: unknown }[]; update: Record<string, unknown> }) => Promise<unknown>;
			};
			await adapter.update({
				model: 'user',
				where: [{ field: 'id', value: session.user.id }],
				update: { email }
			});
		})
	};

	const algIds = options.supportedAlgorithmIDs === false ? null : (options.supportedAlgorithmIDs ?? EXPANDED_SUPPORTED_ALGORITHM_IDS);

	async function onResponse(res: Response, _ctx: AuthContext): Promise<{ response: Response } | void> {
		if (algIds === null) return;
		const ct = res.headers.get('content-type') ?? '';
		if (!ct.includes('application/json')) return;
		let body: unknown;
		try {
			body = await res.clone().json();
		} catch {
			return;
		}
		if (body == null || typeof body !== 'object' || !Array.isArray((body as { pubKeyCredParams?: unknown }).pubKeyCredParams)) return;
		const opts = body as { pubKeyCredParams: { type: string; alg: number }[]; challenge?: string; rp?: unknown };
		if (!opts.challenge && !opts.rp) return;
		opts.pubKeyCredParams = algIds.map((alg) => ({ type: 'public-key' as const, alg }));
		return {
			response: new Response(JSON.stringify(body), {
				status: res.status,
				statusText: res.statusText,
				headers: res.headers
			})
		};
	}

	return {
		id: 'corepass-passkey',
		schema: corepassPasskeySchema,
		onResponse,
		init() {
			const opts: { options?: { databaseHooks?: Record<string, unknown> } } = {};
			if (hasAllowlist) {
				opts.options = {
					databaseHooks: {
						passkey: {
							create: {
								before: async (data: { aaguid?: string | null }, _context: unknown) => {
									const aaguid = data?.aaguid;
									if (!isAaguidAllowed(aaguid ?? undefined, effectiveAllowlist)) {
										throw new APIError('BAD_REQUEST', {
											message: 'Authenticator not allowed by AAGUID policy',
											code: 'AAGUID_NOT_ALLOWED'
										});
									}
									return undefined;
								}
							}
						}
					}
				};
			}
			return opts;
		},
		hooks: { before: [beforeHook], after: [afterHook] },
		endpoints: {
			passkeyDataHead: createHeadEnrichmentEndpoint(options),
			passkeyDataGet: createGetEnrichmentEndpoint(options),
			passkeyData: createEnrichmentEndpoint(options)
		},
		$ERROR_CODES: {
			PASSKEY_REQUIRED: PASSKEY_REQUIRED_ERROR,
			REGISTRATION_TIMEOUT: REGISTRATION_TIMEOUT_ERROR,
			EMAIL_REQUIRED: EMAIL_REQUIRED_ERROR,
			CORE_ID_INVALID: CORE_ID_INVALID_ERROR,
			CORE_ID_NETWORK_NOT_ALLOWED: CORE_ID_NETWORK_NOT_ALLOWED_ERROR,
			BACKED_UP_REQUIRED: BACKED_UP_REQUIRED_ERROR
		}
	};
}

export type { CorePassPluginOptions, EnrichmentBody, EnrichmentUserData } from './types.js';
