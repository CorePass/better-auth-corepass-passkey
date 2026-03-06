/**
 * Better Auth plugin: CorePass enrichment for passkey.
 * Adds POST /webauthn/data for signed enrichment payload, corepass_profile schema, requireO18y/requireO21y/requireKyc.
 * Optional allowedAaguids: passkey create.before hook to allow only listed AAGUIDs.
 * Must be used after @better-auth/passkey.
 */

import { APIError } from 'better-auth/api';
import {
	createEnrichmentEndpoint,
	createGetEnrichmentEndpoint,
	createHeadEnrichmentEndpoint
} from './enrichment-handler.js';
import type { CorePassPluginOptions } from './types.js';

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

export function corepassPasskey(options: CorePassPluginOptions = {}) {
	const allowedAaguids = options.allowedAaguids;
	const hasAllowlist =
		allowedAaguids !== undefined &&
		allowedAaguids !== false &&
		(Array.isArray(allowedAaguids) ? allowedAaguids.length > 0 : typeof allowedAaguids === 'string');

	return {
		id: 'corepass-passkey',
		schema: corepassPasskeySchema,
		init() {
			const opts: { options?: { databaseHooks?: Record<string, unknown> } } = {};
			if (hasAllowlist) {
				opts.options = {
					databaseHooks: {
						passkey: {
							create: {
								before: async (data: { aaguid?: string | null }, _context: unknown) => {
									const aaguid = data?.aaguid;
									if (!isAaguidAllowed(aaguid ?? undefined, allowedAaguids as string | string[])) {
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
		endpoints: {
			passkeyDataHead: createHeadEnrichmentEndpoint(options),
			passkeyDataGet: createGetEnrichmentEndpoint(options),
			passkeyData: createEnrichmentEndpoint(options)
		}
	};
}

export type { CorePassPluginOptions, EnrichmentBody, EnrichmentUserData } from './types.js';
