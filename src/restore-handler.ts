/**
 * Restore endpoints: allow a user who lost their passkey to prove identity via CorePass Ed448 signature
 * and register a new passkey.
 *
 * Flow:
 * 1. Browser:  POST /webauthn/restore/init       → { restoreId, expiresAt, signaturePath }
 * 2. QR code shown to user with restoreId
 * 3. CorePass: POST /webauthn/restore             → signs { coreId, restoreId, timestamp } with Ed448
 * 4. Backend verifies signature, finds user by coreId, deletes old passkeys + sessions, marks challenge verified
 * 5. Browser:  POST /webauthn/restore/complete    → creates session, sets cookie → user can register new passkey
 */

import { createAuthEndpoint, APIError } from 'better-auth/api';
import { setSessionCookie } from 'better-auth/cookies';
import { z } from 'zod';
import { canonicalizeJSON, buildSignatureInput } from './utils/canonical.js';
import {
	parseEd448Signature,
	parseEd448PublicKey,
	publicKeyFromCoreIdLongForm,
	verifyEd448
} from './utils/ed448.js';
import type { CorePassPluginOptions } from './types.js';

const RESTORE_BASE = '/webauthn/restore';
const DEFAULT_CHALLENGE_EXPIRY_MS = 300_000; // 5 minutes
const DEFAULT_TIMESTAMP_WINDOW_MS = 600_000;

type Adapter = {
	findOne: (arg: { model: string; where: { field: string; value: unknown }[] }) => Promise<unknown>;
	update: (arg: {
		model: string;
		where: { field: string; value: unknown }[];
		update: Record<string, unknown>;
	}) => Promise<unknown>;
	create: (arg: { model: string; data: Record<string, unknown> }) => Promise<unknown>;
	delete: (arg: { model: string; where: { field: string; value: unknown }[] }) => Promise<void>;
};

type InternalAdapterDeleteSessions = {
	deleteSessions: (userId: string) => Promise<unknown>;
};

type InternalAdapterCreateSession = {
	createSession: (
		userId: string,
		request?: Request,
		dontRememberMe?: boolean
	) => Promise<unknown>;
	deleteSessions: (userId: string) => Promise<unknown>;
};

/**
 * POST /webauthn/restore/init
 * Browser calls this (unauthenticated) to start the restore flow.
 * Returns a restoreId for the QR code.
 */
export function createRestoreInitEndpoint(options: CorePassPluginOptions) {
	const expiryMs = options.restoreChallengeExpiryMs ?? DEFAULT_CHALLENGE_EXPIRY_MS;

	return createAuthEndpoint(
		`${RESTORE_BASE}/init`,
		{
			method: 'POST',
			body: z.object({}).optional(),
			metadata: {
				openapi: {
					description: 'Generate a restore challenge for passkey recovery via CorePass signature'
				}
			}
		},
		async (ctx) => {
			const adapter = ctx.context.adapter as Adapter;
			const now = Math.floor(Date.now() / 1000);
			const expiresAt = now + Math.floor(expiryMs / 1000);

			const created = (await adapter.create({
				model: 'restore_challenge',
				data: {
					userId: null,
					status: 'pending',
					expiresAt
				}
			})) as { id: string } | null;

			const restoreId = created?.id;
			if (!restoreId) {
				throw new APIError('INTERNAL_SERVER_ERROR', { message: 'Failed to create restore challenge.' });
			}

			return ctx.json({
				restoreId,
				expiresAt,
				signaturePath: options.restoreSignaturePath ?? RESTORE_BASE
			});
		}
	);
}

/**
 * POST /webauthn/restore
 * CorePass calls this after user scans QR code. Sends Ed448-signed payload proving coreId ownership.
 * On success: deletes old passkeys and sessions, marks challenge as verified.
 */
export function createRestoreVerifyEndpoint(options: CorePassPluginOptions) {
	const signaturePath = options.restoreSignaturePath ?? RESTORE_BASE;
	const timestampWindowMs = options.timestampWindowMs ?? DEFAULT_TIMESTAMP_WINDOW_MS;

	const bodySchema = z.object({
		coreId: z.string(),
		restoreId: z.string(),
		timestamp: z.number()
	});

	return createAuthEndpoint(
		RESTORE_BASE,
		{
			method: 'POST',
			body: bodySchema,
			metadata: {
				openapi: {
					description:
						'CorePass sends Ed448-signed restore request to prove coreId ownership and replace lost passkey'
				}
			}
		},
		async (ctx) => {
			const body = ctx.body as z.infer<typeof bodySchema>;
			const { coreId, restoreId, timestamp } = body;

			if (!coreId?.trim() || !restoreId?.trim() || typeof timestamp !== 'number') {
				throw new APIError('BAD_REQUEST', {
					message: 'coreId, restoreId, and timestamp are required.'
				});
			}

			// Validate challenge FIRST (cheap DB check before expensive signature verification)
			const adapter = ctx.context.adapter as Adapter;
			const challenge = await adapter.findOne({
				model: 'restore_challenge',
				where: [{ field: 'id', value: restoreId }]
			});
			if (!challenge) {
				throw new APIError('NOT_FOUND', {
					message: 'Restore challenge not found.',
					code: 'RESTORE_CHALLENGE_NOT_FOUND'
				});
			}
			const ch = challenge as { id: string; status: string; expiresAt: number };
			if (ch.status !== 'pending') {
				throw new APIError('BAD_REQUEST', {
					message: 'Restore challenge already used.',
					code: 'RESTORE_CHALLENGE_USED'
				});
			}
			const now = Math.floor(Date.now() / 1000);
			if (ch.expiresAt < now) {
				throw new APIError('BAD_REQUEST', {
					message: 'Restore challenge expired.',
					code: 'RESTORE_CHALLENGE_EXPIRED'
				});
			}

			// Timestamp window check
			const nowUs = Date.now() * 1000;
			if (Math.abs(timestamp - nowUs) > timestampWindowMs * 1000) {
				throw new APIError('BAD_REQUEST', { message: 'Timestamp out of window.' });
			}

			// Ed448 signature verification (same pattern as enrichment)
			const signatureRaw = ctx.headers?.get('X-Signature');
			if (!signatureRaw) {
				throw new APIError('UNAUTHORIZED', { message: 'X-Signature header required.' });
			}
			const signatureBytes = parseEd448Signature(signatureRaw);
			if (!signatureBytes || signatureBytes.length !== 114) {
				throw new APIError('BAD_REQUEST', { message: 'Invalid X-Signature.' });
			}

			let publicKeyBytes: Uint8Array | null = parseEd448PublicKey(
				ctx.headers?.get('X-Public-Key') ?? ''
			);
			if (!publicKeyBytes) {
				publicKeyBytes = publicKeyFromCoreIdLongForm(coreId);
			}
			if (!publicKeyBytes) {
				throw new APIError('BAD_REQUEST', {
					message: 'Provide long-form Core ID (BBAN 114 hex) or X-Public-Key header.'
				});
			}

			const canonicalBody = canonicalizeJSON({ coreId, restoreId, timestamp });
			const signatureInput = buildSignatureInput('POST', signaturePath, canonicalBody);
			const messageBytes = new TextEncoder().encode(signatureInput);
			const valid = await verifyEd448({ publicKeyBytes, messageBytes, signatureBytes });
			if (!valid) {
				throw new APIError('UNAUTHORIZED', { message: 'Signature verification failed.' });
			}

			// Atomically mark challenge as 'verifying' to prevent concurrent verify calls
			try {
				await adapter.update({
					model: 'restore_challenge',
					where: [{ field: 'id', value: restoreId }],
					update: { status: 'verifying' }
				});
			} catch {
				throw new APIError('BAD_REQUEST', {
					message: 'Restore challenge already used.',
					code: 'RESTORE_CHALLENGE_USED'
				});
			}

			// Find user by coreId — revert challenge if not found
			const coreIdUpper = coreId.trim().toUpperCase();
			const profile = await adapter.findOne({
				model: 'corepass_profile',
				where: [{ field: 'coreId', value: coreIdUpper }]
			});
			if (!profile) {
				// Revert to pending so user can try again with a different coreId (or same QR, new attempt)
				await adapter.update({
					model: 'restore_challenge',
					where: [{ field: 'id', value: restoreId }],
					update: { status: 'pending' }
				}).catch(() => {});
				throw new APIError('NOT_FOUND', {
					message: 'No account found for this Core ID.',
					code: 'CORE_ID_NOT_FOUND'
				});
			}
			const userId = (profile as { userId: string }).userId;

			// Delete all old passkeys for this user
			try {
				await adapter.delete({
					model: 'passkey',
					where: [{ field: 'userId', value: userId }]
				});
			} catch (err) {
				ctx.context.logger?.error?.('Failed to delete old passkeys during restore', err);
			}

			// Delete all old sessions
			const internal = ctx.context.internalAdapter as unknown as InternalAdapterDeleteSessions;
			try {
				await internal.deleteSessions(userId);
			} catch (err) {
				ctx.context.logger?.error?.('Failed to delete old sessions during restore', err);
			}

			// Reset user.createdAt so the deleteAccountWithoutPasskeyAfterMs timeout
			// doesn't immediately kill the account (the old createdAt could be days/weeks ago).
			try {
				await adapter.update({
					model: 'user',
					where: [{ field: 'id', value: userId }],
					update: { createdAt: new Date() }
				});
			} catch (err) {
				ctx.context.logger?.error?.('Failed to reset user.createdAt during restore', err);
			}

			// Mark challenge as verified with the resolved userId
			await adapter.update({
				model: 'restore_challenge',
				where: [{ field: 'id', value: restoreId }],
				update: { status: 'verified', userId }
			});

			return ctx.json({ ok: true });
		}
	);
}

/**
 * POST /webauthn/restore/complete
 * Browser calls this after CorePass has verified the restore.
 * Creates a new session for the user (no passkey yet) and sets the session cookie.
 * The user then goes through normal passkey registration flow.
 */
export function createRestoreCompleteEndpoint(_options: CorePassPluginOptions) {
	const bodySchema = z.object({
		restoreId: z.string()
	});

	return createAuthEndpoint(
		`${RESTORE_BASE}/complete`,
		{
			method: 'POST',
			body: bodySchema,
			metadata: {
				openapi: {
					description:
						'Complete restore flow: exchange verified restoreId for a session (browser-side)'
				}
			}
		},
		async (ctx) => {
			const { restoreId } = ctx.body as z.infer<typeof bodySchema>;
			if (!restoreId?.trim()) {
				throw new APIError('BAD_REQUEST', { message: 'restoreId is required.' });
			}

			const adapter = ctx.context.adapter as Adapter;
			const challenge = await adapter.findOne({
				model: 'restore_challenge',
				where: [{ field: 'id', value: restoreId }]
			});
			if (!challenge) {
				throw new APIError('NOT_FOUND', {
					message: 'Restore challenge not found.',
					code: 'RESTORE_CHALLENGE_NOT_FOUND'
				});
			}

			const ch = challenge as {
				id: string;
				status: string;
				userId: string | null;
				expiresAt: number;
			};

			if (ch.status === 'pending') {
				// CorePass hasn't verified yet — tell browser to keep polling
				return ctx.json({ ok: false, status: 'pending' });
			}
			if (ch.status === 'completed') {
				throw new APIError('BAD_REQUEST', {
					message: 'Restore already completed.',
					code: 'RESTORE_ALREADY_COMPLETED'
				});
			}
			if (ch.status !== 'verified' || !ch.userId) {
				throw new APIError('BAD_REQUEST', {
					message: 'Restore challenge in unexpected state.',
					code: 'RESTORE_INVALID_STATE'
				});
			}

			// Check expiry
			const now = Math.floor(Date.now() / 1000);
			if (ch.expiresAt < now) {
				throw new APIError('BAD_REQUEST', {
					message: 'Restore challenge expired.',
					code: 'RESTORE_CHALLENGE_EXPIRED'
				});
			}

			// Mark as completed FIRST to prevent concurrent /complete calls from creating
			// duplicate sessions (only one caller wins the status transition).
			await adapter.update({
				model: 'restore_challenge',
				where: [{ field: 'id', value: restoreId }],
				update: { status: 'completed' }
			});

			// Verify the user still exists (could have been deleted between verify and complete)
			const user = await adapter.findOne({
				model: 'user',
				where: [{ field: 'id', value: ch.userId }]
			});
			if (!user) {
				throw new APIError('NOT_FOUND', {
					message: 'User account no longer exists. Please register again.',
					code: 'USER_NOT_FOUND'
				});
			}

			// Create session for the user — if this fails, revert challenge so browser can retry
			const internal = ctx.context.internalAdapter as unknown as InternalAdapterCreateSession;
			let sessionRecord: unknown;
			try {
				sessionRecord = await internal.createSession(ch.userId, ctx.request);
			} catch (err) {
				// Revert to verified so the browser can retry /complete
				await adapter.update({
					model: 'restore_challenge',
					where: [{ field: 'id', value: restoreId }],
					update: { status: 'verified' }
				}).catch(() => {});
				ctx.context.logger?.error?.('Failed to create session during restore complete', err);
				throw new APIError('INTERNAL_SERVER_ERROR', {
					message: 'Failed to create session. Please try again.'
				});
			}

			// Set session cookie so the browser is authenticated
			if (sessionRecord) {
				await setSessionCookie(
					ctx,
					{
						session: sessionRecord as Record<string, unknown> & { token: string },
						user: user as Record<string, unknown> & { id: string }
					} as Parameters<typeof setSessionCookie>[1]
				);
			}

			return ctx.json({ ok: true, status: 'completed' });
		}
	);
}
