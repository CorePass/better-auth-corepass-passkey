/**
 * Support flow: a user loses their Core ID entirely, proves identity with documents, and
 * support manually switches corepass_profile.coreId to their NEW Core ID. The user then runs
 * restore to get a passkey on their phone.
 *
 * Enrichment always writes coreId UPPERCASE, and restore looks it up with
 * `coreId.trim().toUpperCase()`. The column is plain `text not null unique` with no
 * COLLATE NOCASE, so SQLite `=` is case-sensitive. If support writes the new Core ID in
 * lowercase — the form used everywhere else in this stack (site config, the signup bridge,
 * block explorers) — the lookup misses.
 *
 * This drives the REAL /webauthn/restore endpoint with a genuine Ed448 signature.
 */

import { betterAuth } from 'better-auth';
import { anonymous } from 'better-auth/plugins';
import { passkey } from '@better-auth/passkey';
import { memoryAdapter } from 'better-auth/adapters/memory';
import { corepassPasskey } from './dist/index.js';
import { ed448 } from '@noble/curves/ed448.js';

let failed = 0;
const ok = (c, n) => { console.log(c ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m', n); if (!c) failed++; };

const AAGUID = '636f7265-7061-7373-6964-656e74697479';
const COREID = 'CB408212E7CF4D5D2B7C83D95550437ED1B37C32B239';
const hex = (b) => Buffer.from(b).toString('hex');
const nowSec = () => Math.floor(Date.now() / 1000);

function build() {
	const db = { user: [], account: [], session: [], verification: [], passkey: [], corepass_profile: [], restore_challenge: [] };
	const auth = betterAuth({
		baseURL: 'http://localhost', basePath: '/auth', secret: 'x'.repeat(40),
		database: memoryAdapter(db), emailAndPassword: { enabled: false },
		plugins: [
			anonymous(),
			passkey({ origin: 'http://localhost', rpID: 'localhost', rpName: 'Wall Money' }),
			corepassPasskey({ finalize: 'after', allowedAaguids: [AAGUID] })
		]
	});
	return { auth, db };
}

/** Run a full CorePass-signed restore against the real endpoint. */
async function attemptRestore(storedCoreId, signedWithCoreId) {
	const { auth, db } = build();
	const ctx = await auth.$context;
	const user = await ctx.internalAdapter.createUser({
		email: 'victim@wall.money', emailVerified: false, isAnonymous: true,
		name: 'CB40…B239', createdAt: new Date(), updatedAt: new Date()
	});
	await ctx.adapter.create({ model: 'passkey', data: {
		userId: user.id, credentialID: 'old-cred', publicKey: 'pk', counter: 0,
		deviceType: 'multiDevice', backedUp: true, transports: 'internal',
		aaguid: AAGUID, createdAt: new Date(), name: 'old'
	}});
	// what support writes after switching the Core ID
	await ctx.adapter.create({ model: 'corepass_profile', data: {
		userId: user.id, coreId: storedCoreId, o18y: 1, o21y: 1, kyc: 1,
		kycDoc: null, backedUp: 0, providedTill: null
	}});
	const ch = await ctx.adapter.create({ model: 'restore_challenge', data: {
		userId: null, status: 'pending', expiresAt: nowSec() + 300
	}});

	const priv = ed448.utils.randomSecretKey ? ed448.utils.randomSecretKey() : ed448.utils.randomPrivateKey();
	const pub = ed448.getPublicKey(priv);
	const payload = { coreId: signedWithCoreId, restoreId: ch.id, timestamp: Date.now() * 1000 };
	const canonical = JSON.stringify({ coreId: payload.coreId, restoreId: payload.restoreId, timestamp: payload.timestamp });
	const sig = ed448.sign(new TextEncoder().encode(`POST\n/webauthn/restore\n${canonical}`), priv);

	const res = await auth.handler(new Request('http://localhost/auth/webauthn/restore', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json', Origin: 'http://localhost',
			'X-Signature': hex(sig), 'X-Public-Key': hex(pub)
		},
		body: JSON.stringify(payload)
	}));
	const body = await res.json().catch(() => ({}));
	const challenge = db.restore_challenge.find((c) => c.id === ch.id);
	return { status: res.status, body, challengeStatus: challenge?.status };
}

console.log('\n── support stored the Core ID UPPERCASE (what enrichment writes) ──');
{
	const r = await attemptRestore(COREID, COREID);
	console.log(`   -> ${r.status} ${JSON.stringify(r.body)}  challenge='${r.challengeStatus}'`);
	ok(r.status === 200 && r.body?.ok === true, 'restore succeeds');
	ok(r.challengeStatus === 'verified', "challenge advances to 'verified' so the browser can continue");
}

console.log('\n── support stored the SAME Core ID lowercase ──');
{
	const r = await attemptRestore(COREID.toLowerCase(), COREID);
	console.log(`   -> ${r.status} ${JSON.stringify(r.body)}  challenge='${r.challengeStatus}'`);
	ok(r.status === 200, `restore should still succeed for the same identity (got ${r.status} ${r.body?.code ?? ''})`);
	ok(r.challengeStatus === 'verified', `challenge should advance (got '${r.challengeStatus}')`);
}

console.log('\n── CorePass signs with a lowercase Core ID, DB holds uppercase ──');
{
	const r = await attemptRestore(COREID, COREID.toLowerCase());
	console.log(`   -> ${r.status} ${JSON.stringify(r.body)}  challenge='${r.challengeStatus}'`);
	ok(r.status === 200, `restore should still succeed (got ${r.status} ${r.body?.code ?? ''})`);
}

console.log(`\n${failed === 0 ? '\x1b[32mall passed\x1b[0m' : `\x1b[31m${failed} failed\x1b[0m`}`);
process.exit(failed === 0 ? 0 : 1);
