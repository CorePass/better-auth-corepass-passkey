/**
 * passkey/data endpoints:
 * - HEAD: only method to verify if /passkey/data is active. 200 if enrichment flow is available (finalize "after"), 404 if not (e.g. "immediate").
 * - POST: receive data from the application (CorePass) for verification. Ed448 signature, requireEmail/requireO18y/requireO21y/requireKyc and coreId; on failure delete user and sessions. On success store enrichment, update user email and name, passkey name.
 */

import { validateWalletAddress } from 'blockchain-wallet-validator';
import { createAuthEndpoint, APIError } from 'better-auth/api';
import { z } from 'zod';
import { canonicalizeJSON, buildSignatureInput } from './utils/canonical.js';
import {
	parseEd448Signature,
	parseEd448PublicKey,
	publicKeyFromCoreIdLongForm,
	verifyEd448
} from './utils/ed448.js';
import { isValidEmail } from './utils/email.js';
import type { CorePassPluginOptions, EnrichmentBody, EnrichmentUserData } from './types.js';

const enrichmentBodySchema = z.object({
	coreId: z.string(),
	credentialId: z.string(),
	timestamp: z.number(),
	userData: z
		.object({
			email: z.string().optional(),
			o18y: z.union([z.boolean(), z.number()]).optional(),
			o21y: z.union([z.boolean(), z.number()]).optional(),
			kyc: z.union([z.boolean(), z.number()]).optional(),
			kycDoc: z.string().optional(),
			dataExp: z.number().optional(),
			backedUp: z.boolean().optional()
		})
		.optional()
});

const DEFAULT_ENRICHMENT_PATH = '/passkey/data';
const DEFAULT_TIMESTAMP_WINDOW_MS = 600_000;

function toBool(v: boolean | number | undefined): boolean {
	if (v === true || v === 1) return true;
	if (v === false || v === 0) return false;
	return false;
}

/** Format Core ID as display name: first 4 chars (uppercase), "…", last 4 chars (uppercase). */
function coreIdToDisplayName(coreId: string): string {
	const s = coreId.trim();
	const first4 = s.slice(0, 4).toUpperCase();
	const last4 = s.slice(-4).toUpperCase();
	return `${first4}…${last4}`;
}

/** HEAD /passkey/data: 200 if enrichment flow is available (finalize "after"), 404 if immediate. */
export function createHeadEnrichmentEndpoint(options: CorePassPluginOptions) {
	const finalize = options.finalize ?? 'after';
	return createAuthEndpoint(
		DEFAULT_ENRICHMENT_PATH,
		{
			method: 'HEAD',
			metadata: {
				openapi: {
					description: 'Check if CorePass enrichment endpoint is available (200 = yes, 404 = no)'
				}
			}
		},
		async (ctx) => {
			if (finalize === 'after') {
				return new Response(null, { status: 200 });
			}
			return new Response(null, { status: 404 });
		}
	);
}

export function createEnrichmentEndpoint(options: CorePassPluginOptions) {
	const signaturePath = options.signaturePath ?? DEFAULT_ENRICHMENT_PATH;
	const timestampWindowMs = options.timestampWindowMs ?? DEFAULT_TIMESTAMP_WINDOW_MS;

	return createAuthEndpoint(
		DEFAULT_ENRICHMENT_PATH,
		{
			method: 'POST',
			body: enrichmentBodySchema,
			metadata: {
				openapi: {
					description: 'CorePass enrichment: signed payload to attach identity and profile to a passkey registration'
				}
			}
		},
		async (ctx) => {
			const body = ctx.body as EnrichmentBody;
			const { coreId, credentialId, timestamp, userData } = body;
			if (!coreId || !credentialId || typeof timestamp !== 'number') {
				throw new APIError('BAD_REQUEST', { message: 'coreId, credentialId, and timestamp are required.' });
			}

			const nowUs = Date.now() * 1000;
			if (Math.abs(timestamp - nowUs) > timestampWindowMs * 1000) {
				throw new APIError('BAD_REQUEST', { message: 'timestamp out of window.' });
			}

			const signatureRaw = ctx.headers?.get('X-Signature');
			if (!signatureRaw) {
				throw new APIError('UNAUTHORIZED', { message: 'X-Signature header required.' });
			}
			const signatureBytes = parseEd448Signature(signatureRaw);
			if (!signatureBytes || signatureBytes.length !== 114) {
				throw new APIError('BAD_REQUEST', { message: 'Invalid X-Signature.' });
			}

			let publicKeyBytes: Uint8Array | null = parseEd448PublicKey(ctx.headers?.get('X-Public-Key') ?? '');
			if (!publicKeyBytes) {
				publicKeyBytes = publicKeyFromCoreIdLongForm(coreId);
			}
			if (!publicKeyBytes) {
				throw new APIError('BAD_REQUEST', {
					message: 'Provide long-form Core ID (BBAN 114 hex) or X-Public-Key header.'
				});
			}

			const canonicalBody = canonicalizeJSON({
				coreId,
				credentialId,
				timestamp,
				userData: userData ?? {}
			});
			const signatureInput = buildSignatureInput('POST', signaturePath, canonicalBody);
			const messageBytes = new TextEncoder().encode(signatureInput);
			const valid = await verifyEd448({
				publicKeyBytes,
				messageBytes,
				signatureBytes
			});
			if (!valid) {
				throw new APIError('UNAUTHORIZED', { message: 'Signature verification failed.' });
			}

			const adapter = ctx.context.adapter as Adapter;
			const passkey = await adapter.findOne({
				model: 'passkey',
				where: [{ field: 'credentialID', value: credentialId }]
			});
			if (!passkey) {
				throw new APIError('NOT_FOUND', { message: 'Passkey not found for this credential.' });
			}
			const userId = (passkey as { userId: string }).userId;

			const data = (userData ?? {}) as EnrichmentUserData;
			const failAndClean = async (err: APIError) => {
				const internal = ctx.context.internalAdapter as { deleteUser: (id: string) => Promise<unknown>; deleteSessions: (userId: string) => Promise<unknown> };
				try {
					await internal.deleteSessions(userId);
					await internal.deleteUser(userId);
				} catch (e) {
					ctx.context.logger?.error?.('Failed to clean account after enrichment validation failure', e);
				}
				throw err;
			};

			if (!coreId?.trim()) {
				await failAndClean(new APIError('BAD_REQUEST', { message: 'Core ID is required.' }));
			}
			if (options.requireO18y && !toBool(data.o18y)) {
				await failAndClean(new APIError('BAD_REQUEST', { message: 'You must be at least 18.' }));
			}
			if (options.requireO21y && !toBool(data.o21y)) {
				await failAndClean(new APIError('BAD_REQUEST', { message: 'You must be at least 21.' }));
			}
			if (options.requireKyc && !toBool(data.kyc)) {
				await failAndClean(new APIError('BAD_REQUEST', { message: 'You need to be KYCed to register.' }));
			}
			if (options.requireEmail) {
				const enrichmentEmail = typeof data.email === 'string' ? data.email.trim() : '';
				if (!isValidEmail(enrichmentEmail)) {
					await failAndClean(new APIError('BAD_REQUEST', { message: 'Valid email required.' }));
				}
			}
			if (options.allowOnlyBackedUp && !toBool(data.backedUp)) {
				await failAndClean(new APIError('BAD_REQUEST', {
					message: 'Back up CorePass passphrase first.',
					code: 'BACKED_UP_REQUIRED'
				}));
			}

			const coreIdTrimmed = coreId.trim();
			const rawAllow = options.allowNetwork;
			const allowedNetworks = ((): Set<'mainnet' | 'testnet' | 'enterprise'> => {
				if (rawAllow === true) return new Set(['mainnet']);
				if (rawAllow === false) return new Set(['testnet']);
				if (Array.isArray(rawAllow) && rawAllow.length > 0) return new Set(rawAllow);
				return new Set(['mainnet', 'enterprise']);
			})();
			const coreValidation = validateWalletAddress(coreIdTrimmed, {
				network: ['xcb'],
				testnet: true
			});
			if (!coreValidation.isValid) {
				await failAndClean(new APIError('BAD_REQUEST', {
					message: 'Valid Core ID required.',
					code: 'CORE_ID_INVALID'
				}));
			}
			const meta = coreValidation.metadata as { isTestnet?: boolean; isEnterprise?: boolean } | undefined;
			const isTestnet = meta?.isTestnet === true;
			const isEnterprise = meta?.isEnterprise === true;
			const network: 'mainnet' | 'testnet' | 'enterprise' = isTestnet ? 'testnet' : isEnterprise ? 'enterprise' : 'mainnet';
			if (!allowedNetworks.has(network)) {
				await failAndClean(new APIError('BAD_REQUEST', {
					message: `Must use Core ${network}.`,
					code: 'CORE_ID_NETWORK_NOT_ALLOWED'
				}));
			}

			const coreIdUpper = coreIdTrimmed.toUpperCase();
			const rawEnrichmentEmail = typeof data.email === 'string' ? data.email.trim() : '';
			const enrichmentEmailValue = isValidEmail(rawEnrichmentEmail) ? rawEnrichmentEmail : null;
			const dataExpMinutes = typeof data.dataExp === 'number' ? data.dataExp : null;
			const providedTill =
				dataExpMinutes != null ? Math.floor(Date.now() / 1000) + dataExpMinutes * 60 : null;

			await adapter.update({
				model: 'passkey',
				where: [{ field: 'id', value: (passkey as { id: string }).id }],
				update: { name: coreIdUpper }
			});

			const userBefore = (await adapter.findOne({
				model: 'user',
				where: [{ field: 'id', value: userId }]
			})) as { email?: string | null } | null;
			const rawRegistrationEmail = userBefore?.email?.trim() || null;
			const registrationEmail = isValidEmail(rawRegistrationEmail) ? rawRegistrationEmail : null;
			const effectiveEmail = enrichmentEmailValue ?? registrationEmail;

			const userUpdate: Record<string, unknown> = {
				name: coreIdToDisplayName(coreId)
			};
			if (enrichmentEmailValue) userUpdate.email = enrichmentEmailValue;
			await adapter.update({
				model: 'user',
				where: [{ field: 'id', value: userId }],
				update: userUpdate
			});

			if (options.requireAtLeastOneEmail && !isValidEmail(effectiveEmail)) {
				await failAndClean(new APIError('BAD_REQUEST', {
					message: 'Registration requires a valid email address.'
				}));
			}

			const profileUpdate = {
				userId,
				coreId: coreIdUpper,
				o18y: toBool(data.o18y) ? 1 : 0,
				o21y: toBool(data.o21y) ? 1 : 0,
				kyc: toBool(data.kyc) ? 1 : 0,
				kycDoc: data.kycDoc ?? null,
				backedUp: toBool(data.backedUp) ? 1 : 0,
				providedTill
			};
			await upsertCorePassProfile(ctx, profileUpdate);

			return ctx.json({ ok: true }, { status: 200 });
		}
	);
}

type Adapter = {
	findOne: (arg: { model: string; where: { field: string; value: unknown }[] }) => Promise<unknown>;
	update: (arg: {
		model: string;
		where: { field: string; value: unknown }[];
		update: Record<string, unknown>;
	}) => Promise<unknown>;
	create: (arg: { model: string; data: Record<string, unknown> }) => Promise<unknown>;
};

async function upsertCorePassProfile(
	ctx: { context: { adapter: unknown } },
	profile: {
		userId: string;
		coreId: string;
		o18y: number;
		o21y: number;
		kyc: number;
		kycDoc: string | null;
		backedUp: number;
		providedTill: number | null;
	}
): Promise<void> {
	const adapter = ctx.context.adapter as Adapter;
	const existing = await adapter.findOne({
		model: 'corepass_profile',
		where: [{ field: 'userId', value: profile.userId }]
	});
	if (existing) {
		await adapter.update({
			model: 'corepass_profile',
			where: [{ field: 'userId', value: profile.userId }],
			update: {
				coreId: profile.coreId,
				o18y: profile.o18y,
				o21y: profile.o21y,
				kyc: profile.kyc,
				kycDoc: profile.kycDoc,
				backedUp: profile.backedUp,
				providedTill: profile.providedTill
			}
		});
	} else {
		await adapter.create({
			model: 'corepass_profile',
			data: profile as unknown as Record<string, unknown>
		});
	}
}
