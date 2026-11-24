/**
 * Better Auth 1.7 gives anonymous users `<id>@anonymous.placeholder.invalid`, not the old
 * `temp@<id>.com`. The plugin only recognised the old form, so it took the new placeholder for
 * a real address: an unfinished registration was never reclaimed (the next attempt got
 * CORE_ID_TAKEN), and requireAtLeastOneEmail let accounts through with no email at all.
 *
 * The anonymous users here come from the REAL /sign-in/anonymous, so the placeholder is
 * whatever this Better Auth version generates.
 */

import { betterAuth } from 'better-auth';
import { anonymous } from 'better-auth/plugins';
import { passkey } from '@better-auth/passkey';
import { memoryAdapter } from 'better-auth/adapters/memory';
import { corepassPasskey } from './dist/index.js';
import { isAnonymousPlaceholderEmail, isRealUserEmail } from './dist/utils/email.js';
import { newCorePassKey, signedHeaders } from './test-keys.mjs';

let failed = 0;
const ok = (c, n) => { console.log(c ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m', n); if (!c) failed++; };

const AAGUID = '636f7265-7061-7373-6964-656e74697479';

function build(opts = {}) {
	const db = { user: [], account: [], session: [], verification: [], passkey: [], corepass_profile: [], restore_challenge: [] };
	const auth = betterAuth({
		baseURL: 'http://localhost', basePath: '/auth', secret: 'x'.repeat(40),
		database: memoryAdapter(db), emailAndPassword: { enabled: false },
		logger: { disabled: true },
		plugins: [
			anonymous(),
			passkey({ origin: 'http://localhost', rpID: 'localhost', rpName: 'Wall Money' }),
			corepassPasskey({ finalize: 'after', allowedAaguids: [AAGUID], ...opts })
		]
	});
	return { auth, db };
}

/** A real anonymous sign-in plus a registered passkey: what a registration looks like before enrichment. */
async function anonymousRegistration(auth, db, credentialId) {
	await auth.handler(new Request('http://localhost/auth/sign-in/anonymous', {
		method: 'POST', headers: { 'Content-Type': 'application/json', Origin: 'http://localhost' }, body: '{}'
	}));
	const user = db.user[db.user.length - 1];
	const ctx = await auth.$context;
	await ctx.adapter.create({ model: 'passkey', data: {
		userId: user.id, credentialID: credentialId, publicKey: 'pk', counter: 0, deviceType: 'multiDevice',
		backedUp: true, transports: 'internal', aaguid: AAGUID, createdAt: new Date(), name: 'Wall Money'
	}});
	return user;
}

async function enrich(auth, { key, credentialId, email }) {
	const userData = email ? { email, kyc: true, o18y: true, o21y: true } : { kyc: true, o18y: true, o21y: true };
	const payload = { coreId: key.coreId, credentialId, timestamp: Date.now() * 1000, userData };
	const canonical = JSON.stringify({ coreId: key.coreId, credentialId, timestamp: payload.timestamp, userData });
	const res = await auth.handler(new Request('http://localhost/auth/webauthn/data', {
		method: 'POST', headers: signedHeaders(key, '/webauthn/data', canonical), body: JSON.stringify(payload)
	}));
	return { status: res.status, body: await res.json().catch(() => ({})) };
}

console.log('\n── which addresses are placeholders ──');
{
	for (const email of [
		'pqy607knmvtolqipfod7q2hbvelhu8hu@anonymous.placeholder.invalid',
		'temp-abc123@example.com',
		'temp@abc123.com',
		'someone@anything.invalid'
	]) {
		ok(isAnonymousPlaceholderEmail(email) && !isRealUserEmail(email), `placeholder: ${email}`);
	}
	for (const email of ['owner@wall.money', 'temporary@wall.money', 'temp.user@wall.money', 'me@invalid.com', 'me@notinvalid']) {
		ok(!isAnonymousPlaceholderEmail(email), `real address: ${email}`);
	}
}

console.log('\n── this Better Auth version\'s placeholder is recognised ──');
{
	const { auth, db } = build();
	const user = await anonymousRegistration(auth, db, 'probe-cred');
	console.log(`   anonymous user email: ${user.email}`);
	ok(isAnonymousPlaceholderEmail(user.email), 'the generated email counts as a placeholder');
}

console.log('\n── an unfinished registration is reclaimed by the Core ID\'s owner ──');
{
	const { auth, db } = build();
	const key = newCorePassKey();
	// First attempt: profile written, but the real email never arrived.
	const orphan = await anonymousRegistration(auth, db, 'first-cred');
	const ctx = await auth.$context;
	await ctx.adapter.create({ model: 'corepass_profile', data: {
		userId: orphan.id, coreId: key.coreId, o18y: 1, o21y: 1, kyc: 1, kycDoc: null, backedUp: 0, providedTill: null
	}});
	// Second attempt by the same person.
	const fresh = await anonymousRegistration(auth, db, 'second-cred');
	const r = await enrich(auth, { key, credentialId: 'second-cred', email: 'owner@wall.money' });
	ok(r.status === 200, `the second attempt succeeds (got ${r.status} ${r.body?.code ?? ''})`);
	ok(!db.user.some((u) => u.id === orphan.id), 'the unfinished first registration is removed');
	ok(db.corepass_profile.some((p) => p.userId === fresh.id && p.coreId === key.coreId), 'the Core ID is bound to the new account');
}

console.log('\n── requireAtLeastOneEmail: enrichment without any real email is refused ──');
{
	const { auth, db } = build({ requireAtLeastOneEmail: true });
	const key = newCorePassKey();
	const user = await anonymousRegistration(auth, db, 'no-email-cred');
	const r = await enrich(auth, { key, credentialId: 'no-email-cred' });
	ok(r.status === 400, `refused (got ${r.status} ${r.body?.message ?? ''})`);
	ok(!db.user.some((u) => u.id === user.id), 'and the registration is cleaned up, as documented');
}

console.log('\n── requireAtLeastOneEmail: enrichment with an email still works ──');
{
	const { auth, db } = build({ requireAtLeastOneEmail: true });
	const key = newCorePassKey();
	const user = await anonymousRegistration(auth, db, 'email-cred');
	const r = await enrich(auth, { key, credentialId: 'email-cred', email: 'owner@wall.money' });
	ok(r.status === 200, `succeeds (got ${r.status} ${r.body?.message ?? ''})`);
	ok(db.user.find((u) => u.id === user.id)?.email === 'owner@wall.money', 'and the real email replaces the placeholder');
}

console.log(`\n${failed === 0 ? '\x1b[32mall passed\x1b[0m' : `\x1b[31m${failed} failed\x1b[0m`}`);
process.exit(failed === 0 ? 0 : 1);
