/**
 * Account takeover: restore and enrichment verified the Ed448 signature against whatever key
 * arrived in X-Public-Key, but never checked that the key belongs to the Core ID in the body.
 * Anyone could sign with their own key and claim someone else's Core ID.
 *
 * These drive the REAL endpoints with genuine signatures from an attacker's key.
 */

import { betterAuth } from 'better-auth';
import { anonymous } from 'better-auth/plugins';
import { passkey } from '@better-auth/passkey';
import { memoryAdapter } from 'better-auth/adapters/memory';
import { corepassPasskey } from './dist/index.js';
import { coreIdMatchesPublicKey } from './dist/utils/core-id.js';
import { coreIdForPublicKey, newCorePassKey, signedHeaders } from './test-keys.mjs';

let failed = 0;
const ok = (c, n) => { console.log(c ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m', n); if (!c) failed++; };

const AAGUID = '636f7265-7061-7373-6964-656e74697479';
const nowSec = () => Math.floor(Date.now() / 1000);

function build(opts = {}) {
	const db = { user: [], account: [], session: [], verification: [], passkey: [], corepass_profile: [], restore_challenge: [] };
	const warnings = [];
	const auth = betterAuth({
		baseURL: 'http://localhost', basePath: '/auth', secret: 'x'.repeat(40),
		database: memoryAdapter(db), emailAndPassword: { enabled: false },
		logger: { level: 'warn', log: (level, message) => { if (level === 'warn') warnings.push(message); } },
		plugins: [
			anonymous(),
			passkey({ origin: 'http://localhost', rpID: 'localhost', rpName: 'Wall Money' }),
			corepassPasskey({ finalize: 'after', allowedAaguids: [AAGUID], ...opts })
		]
	});
	return { auth, db, warnings };
}

async function seedAccount(auth, { coreId, email, credentialID = 'victim-cred' }) {
	const ctx = await auth.$context;
	const user = await ctx.internalAdapter.createUser({
		email, emailVerified: false, isAnonymous: true, name: 'victim',
		createdAt: new Date(), updatedAt: new Date()
	});
	await ctx.adapter.create({ model: 'passkey', data: {
		userId: user.id, credentialID, publicKey: 'pk', counter: 0, deviceType: 'multiDevice',
		backedUp: true, transports: 'internal', aaguid: AAGUID, createdAt: new Date(), name: credentialID
	}});
	await ctx.adapter.create({ model: 'corepass_profile', data: {
		userId: user.id, coreId, o18y: 1, o21y: 1, kyc: 1, kycDoc: null, backedUp: 0, providedTill: null
	}});
	await ctx.internalAdapter.createSession(user.id);
	return user;
}

async function restore(auth, { coreId, signer }) {
	const ctx = await auth.$context;
	const ch = await ctx.adapter.create({ model: 'restore_challenge', data: {
		userId: null, status: 'pending', expiresAt: nowSec() + 300
	}});
	const payload = { coreId, restoreId: ch.id, timestamp: Date.now() * 1000 };
	const canonical = JSON.stringify(payload);
	const res = await auth.handler(new Request('http://localhost/auth/webauthn/restore', {
		method: 'POST', headers: signedHeaders(signer, '/webauthn/restore', canonical), body: JSON.stringify(payload)
	}));
	return { res, body: await res.json().catch(() => ({})), restoreId: ch.id };
}

async function enrich(auth, { coreId, signer, credentialId, email }) {
	const payload = {
		coreId, credentialId, timestamp: Date.now() * 1000,
		userData: { email, o18y: true, o21y: true, kyc: true }
	};
	const canonical = JSON.stringify({
		coreId, credentialId, timestamp: payload.timestamp,
		userData: { email, kyc: true, o18y: true, o21y: true }
	});
	const res = await auth.handler(new Request('http://localhost/auth/webauthn/data', {
		method: 'POST', headers: signedHeaders(signer, '/webauthn/data', canonical), body: JSON.stringify(payload)
	}));
	return { res, body: await res.json().catch(() => ({})) };
}

async function freshRegistration(auth, credentialId) {
	const ctx = await auth.$context;
	const user = await ctx.internalAdapter.createUser({
		email: `temp@${credentialId}.com`, emailVerified: false, isAnonymous: true,
		name: 'Anonymous', createdAt: new Date(), updatedAt: new Date()
	});
	await ctx.adapter.create({ model: 'passkey', data: {
		userId: user.id, credentialID: credentialId, publicKey: 'pk', counter: 0, deviceType: 'multiDevice',
		backedUp: true, transports: 'internal', aaguid: AAGUID, createdAt: new Date(), name: 'Wall Money'
	}});
	return user;
}

const victim = newCorePassKey();
const attacker = newCorePassKey();

console.log('\n── the key ↔ Core ID rule ──');
{
	const short = coreIdForPublicKey(victim.pub);
	ok(coreIdMatchesPublicKey(short, victim.pub), 'a Core ID matches the key it was derived from');
	ok(coreIdMatchesPublicKey(short.toUpperCase(), victim.pub), 'case does not matter');
	ok(coreIdMatchesPublicKey(short.replace(/(.{4})/g, '$1 ').trim(), victim.pub), 'spacing does not matter');
	ok(!coreIdMatchesPublicKey(short, attacker.pub), 'another key does not match');
	const badChecksum = `${short.slice(0, 2)}${short[2] === '9' ? '0' : '9'}${short.slice(3)}`;
	ok(!coreIdMatchesPublicKey(badChecksum, victim.pub), 'a wrong checksum does not match');
	ok(coreIdMatchesPublicKey(coreIdForPublicKey(victim.pub, 'ab'), victim.pub), 'Devin testnet (ab) derives the same way');
	ok(!coreIdMatchesPublicKey(`xx${short.slice(2)}`, victim.pub), 'an unknown network prefix does not match');
	const longForm = `cb00${Buffer.from(victim.pub).toString('hex')}`;
	ok(coreIdMatchesPublicKey(longForm, victim.pub), 'a long-form Core ID carries its key');
	ok(!coreIdMatchesPublicKey(longForm, attacker.pub), 'a long-form Core ID refuses any other key');
}

console.log('\n── restore with the attacker\'s own key for the victim\'s Core ID ──');
{
	const { auth, db } = build();
	const user = await seedAccount(auth, { coreId: victim.coreId, email: 'victim@wall.money' });
	const sessionsBefore = db.session.filter((s) => s.userId === user.id).length;
	const r = await restore(auth, { coreId: victim.coreId, signer: attacker });
	const challenge = db.restore_challenge.find((c) => c.id === r.restoreId);
	ok(r.res.status === 401 && r.body?.code === 'PUBLIC_KEY_MISMATCH', `refused with 401 PUBLIC_KEY_MISMATCH (got ${r.res.status} ${r.body?.code})`);
	ok(challenge?.status === 'pending' && !challenge?.userId, 'the challenge is not bound to the victim, so /complete gives no session');
	ok(db.session.filter((s) => s.userId === user.id).length === sessionsBefore, "the victim's sessions are untouched");
}

console.log('\n── restore signed by the Core ID\'s own key still works ──');
{
	const { auth, db } = build();
	const user = await seedAccount(auth, { coreId: victim.coreId, email: 'victim@wall.money' });
	const r = await restore(auth, { coreId: victim.coreId, signer: victim });
	const challenge = db.restore_challenge.find((c) => c.id === r.restoreId);
	ok(r.res.status === 200, `succeeds (got ${r.res.status} ${r.body?.code ?? ''})`);
	ok(challenge?.status === 'verified' && challenge?.userId === user.id, 'and binds the challenge to the owner');
}

console.log('\n── enrichment with the attacker\'s key: no binding, no reclaim ──');
{
	const { auth, db } = build();
	// The victim's half-finished registration: anonymous placeholder email, so it would be "reclaimed".
	const orphan = await seedAccount(auth, { coreId: victim.coreId, email: 'temp@orphan.com' });
	const attackerUser = await freshRegistration(auth, 'attacker-cred');
	const r = await enrich(auth, { coreId: victim.coreId, signer: attacker, credentialId: 'attacker-cred', email: 'evil@example.com' });
	ok(r.res.status === 401 && r.body?.code === 'PUBLIC_KEY_MISMATCH', `refused with 401 PUBLIC_KEY_MISMATCH (got ${r.res.status} ${r.body?.code})`);
	ok(db.user.some((u) => u.id === orphan.id), "the victim's registration is not deleted as an orphan");
	ok(db.corepass_profile.every((p) => p.userId !== attackerUser.id), "the victim's Core ID is not bound to the attacker");
	ok(db.user.find((u) => u.id === attackerUser.id)?.email !== 'evil@example.com', "the attacker's account is not updated either");
}

console.log('\n── enrichment signed by the Core ID\'s own key still works ──');
{
	const { auth, db } = build();
	const user = await freshRegistration(auth, 'owner-cred');
	const r = await enrich(auth, { coreId: victim.coreId, signer: victim, credentialId: 'owner-cred', email: 'owner@wall.money' });
	ok(r.res.status === 200, `succeeds (got ${r.res.status} ${r.body?.code ?? ''})`);
	ok(db.corepass_profile.some((p) => p.userId === user.id && p.coreId === victim.coreId), 'and binds the Core ID to that account');
}

console.log('\n── enrichment finds an existing owner whatever the stored case ──');
{
	const { auth, db } = build();
	// A real account whose row was written by hand in lowercase (e.g. by support).
	const owner = await seedAccount(auth, { coreId: victim.coreId.toLowerCase(), email: 'owner@wall.money' });
	const second = await freshRegistration(auth, 'second-cred');
	const r = await enrich(auth, { coreId: victim.coreId, signer: victim, credentialId: 'second-cred', email: 'other@wall.money' });
	ok(r.body?.code === 'CORE_ID_TAKEN', `a second account is refused with CORE_ID_TAKEN (got ${r.res.status} ${r.body?.code})`);
	ok(db.corepass_profile.filter((p) => p.coreId.toUpperCase() === victim.coreId).length === 1, 'the Core ID stays bound once');
	ok(db.user.some((u) => u.id === owner.id) && !db.user.some((u) => u.id === second.id), 'the owner keeps it; the half-registration is cleaned up');
}

console.log("\n── publicKeyMismatch: 'log' only warns (staging check, never production) ──");
{
	const { auth, db, warnings } = build({ publicKeyMismatch: 'log' });
	await seedAccount(auth, { coreId: victim.coreId, email: 'victim@wall.money' });
	const r = await restore(auth, { coreId: victim.coreId, signer: attacker });
	ok(r.res.status === 200, `the request goes through (got ${r.res.status})`);
	ok(warnings.some((w) => String(w).includes('does not belong to the claimed Core ID')), 'and the mismatch is logged');
	ok(db.restore_challenge.find((c) => c.id === r.restoreId)?.status === 'verified', "which is exactly the takeover 'reject' prevents");
}

console.log(`\n${failed === 0 ? '\x1b[32mall passed\x1b[0m' : `\x1b[31m${failed} failed\x1b[0m`}`);
process.exit(failed === 0 ? 0 : 1);
