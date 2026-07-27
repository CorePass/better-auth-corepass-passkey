/**
 * Regression tests for the restore/registration fixes.
 *
 *   A) Restore verification does NOT delete existing passkeys. Revocation is deferred
 *      until a replacement credential actually exists, so an abandoned restore leaves
 *      the account exactly as it was instead of stranding it with zero credentials.
 *   B) Registering the replacement passkey revokes the old ones and marks the restore
 *      challenge finalized.
 *   C) A stale (expired) completed challenge does NOT revoke anything — adding a second
 *      passkey later must not wipe the first.
 *   D) The requireAtLeastOneEmail gate BLOCKS instead of deleting the account, and keeps
 *      /webauthn/data reachable so enrichment can still supply the missing email.
 *   E) The AAGUID allowlist is actually enforced (it previously relied on a database
 *      hook that never fires, because @better-auth/passkey writes via adapter.create()).
 *
 * Run: node test-restore-revocation.mjs   (from the web-portal dir, see PLUGIN_PATH)
 */

import { betterAuth } from 'better-auth';
import { anonymous } from 'better-auth/plugins';
import { passkey } from '@better-auth/passkey';
import { memoryAdapter } from 'better-auth/adapters/memory';
import { corepassPasskey } from './dist/index.js';

let failed = 0;
const ok = (c, n) => { console.log(c ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m', n); if (!c) failed++; };

const AAGUID = '636f7265-7061-7373-6964-656e74697479';
const COREID = 'CB408212E7CF4D5D2B7C83D95550437ED1B37C32B239';

function build(opts = {}) {
	const db = { user: [], account: [], session: [], verification: [], passkey: [], corepass_profile: [], restore_challenge: [] };
	const auth = betterAuth({
		baseURL: 'http://localhost', basePath: '/auth', secret: 'x'.repeat(40),
		database: memoryAdapter(db), emailAndPassword: { enabled: false },
		plugins: [
			anonymous(),
			passkey({ origin: 'http://localhost', rpID: 'localhost', rpName: 'Wall Money' }),
			corepassPasskey({ finalize: 'after', allowedAaguids: [AAGUID], ...opts })
		]
	});
	return { auth, db };
}

const nowSec = () => Math.floor(Date.now() / 1000);

async function seedUser(auth, db, { email, passkeys = [], aaguid = AAGUID }) {
	const ctx = await auth.$context;
	const user = await ctx.internalAdapter.createUser({
		email, emailVerified: false, isAnonymous: true, name: 'CB40…B239',
		createdAt: new Date(), updatedAt: new Date()
	});
	for (const cid of passkeys) {
		await ctx.adapter.create({ model: 'passkey', data: {
			userId: user.id, credentialID: cid, publicKey: 'pk', counter: 0,
			deviceType: 'multiDevice', backedUp: true, transports: 'internal',
			aaguid, createdAt: new Date(), name: cid
		}});
	}
	await ctx.adapter.create({ model: 'corepass_profile', data: {
		userId: user.id, coreId: COREID,
		o18y: 1, o21y: 1, kyc: 1, kycDoc: null, backedUp: 0, providedTill: null
	}});
	return user;
}

/** Drive the plugin's verify-registration after-hook the way Better Auth does. */
async function simulateVerifyRegistration(auth, { userId, credentialID, aaguid = AAGUID }) {
	const ctx = await auth.$context;
	const created = await ctx.adapter.create({ model: 'passkey', data: {
		userId, credentialID, publicKey: 'pk', counter: 0, deviceType: 'multiDevice',
		backedUp: true, transports: 'internal', aaguid, createdAt: new Date(), name: credentialID
	}});
	const plugin = auth.options.plugins.find((p) => p.id === 'corepass-passkey');
	// Better Auth runs every after-hook whose matcher passes, not just the first —
	// and the plugin's generic afterHook matches everything.
	const hooks = plugin.hooks.after.filter((h) => h.matcher({ path: '/auth/passkey/verify-registration' }));
	if (hooks.length === 0) throw new Error('verify-registration after-hook is not registered');
	// Pass the real AuthContext (spreading it drops prototype accessors such as `adapter`),
	// with `returned` set the way Better Auth sets it for an after-hook.
	ctx.returned = created;
	const hookCtx = {
		path: '/auth/passkey/verify-registration',
		method: 'POST',
		context: ctx,
		headers: new Headers()
	};
	for (const h of hooks) await h.handler(hookCtx);
	return created;
}

console.log('\n── A: restore verification leaves existing passkeys alone ──');
{
	const { auth, db } = build();
	const user = await seedUser(auth, db, { email: 'a@wall.money', passkeys: ['old-cred'] });
	const ctx = await auth.$context;
	await ctx.internalAdapter.createSession(user.id);   // so "sessions revoked" is a real assertion
	const ch = await ctx.adapter.create({ model: 'restore_challenge', data: {
		userId: null, status: 'pending', expiresAt: nowSec() + 300
	}});

	// Drive the REAL endpoint with a genuine Ed448 signature. The handler prefers the
	// X-Public-Key header over deriving the key from a long-form Core ID, so a throwaway
	// keypair works while coreId stays a valid mainnet ICAN.
	const { ed448 } = await import('@noble/curves/ed448.js');
	const priv = ed448.utils.randomSecretKey ? ed448.utils.randomSecretKey() : ed448.utils.randomPrivateKey();
	const pub = ed448.getPublicKey(priv);
	const hex = (b) => Buffer.from(b).toString('hex');

	const payload = { coreId: COREID, restoreId: ch.id, timestamp: Date.now() * 1000 };
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
	// Without this the rest of the test is vacuous: a rejected restore trivially deletes nothing.
	ok(res.status === 200 && body?.ok === true, `restore verify really succeeded (got ${res.status} ${JSON.stringify(body)})`);
	const chAfter = db.restore_challenge.find((c) => c.id === ch.id);
	ok(chAfter?.status === 'verified' && chAfter?.userId === user.id, `challenge verified and bound to the user (got '${chAfter?.status}')`);

	ok(db.passkey.filter((p) => p.userId === user.id).length === 1,
		'old passkey SURVIVES restore verification (abandoning restore no longer strands the account)');
	ok(db.session.filter((s) => s.userId === user.id).length === 0,
		'sessions ARE still revoked immediately (other devices lose access now)');
}

console.log('\n── B: registering the replacement revokes the old credential ──');
{
	const { auth, db } = build();
	const user = await seedUser(auth, db, { email: 'b@wall.money', passkeys: ['old-cred'] });
	const ctx = await auth.$context;
	const ch = await ctx.adapter.create({ model: 'restore_challenge', data: {
		userId: user.id, status: 'completed', expiresAt: nowSec() + 300
	}});

	await simulateVerifyRegistration(auth, { userId: user.id, credentialID: 'new-cred' });

	const left = db.passkey.filter((p) => p.userId === user.id).map((p) => p.credentialID);
	ok(left.length === 1 && left[0] === 'new-cred', `only the replacement remains (got ${JSON.stringify(left)})`);
	const after = db.restore_challenge.find((c) => c.id === ch.id);
	ok(after.status === 'finalized', `challenge marked finalized (got '${after.status}')`);
}

console.log('\n── C: a stale completed challenge must not revoke anything ──');
{
	const { auth, db } = build();
	const user = await seedUser(auth, db, { email: 'c@wall.money', passkeys: ['first-cred'] });
	const ctx = await auth.$context;
	await ctx.adapter.create({ model: 'restore_challenge', data: {
		userId: user.id, status: 'completed', expiresAt: nowSec() - 60 // expired
	}});

	await simulateVerifyRegistration(auth, { userId: user.id, credentialID: 'second-cred' });

	const left = db.passkey.filter((p) => p.userId === user.id).map((p) => p.credentialID).sort();
	ok(left.length === 2, `both passkeys kept when the restore is stale (got ${JSON.stringify(left)})`);
}

console.log('\n── D: requireAtLeastOneEmail blocks instead of deleting ──');
{
	const { auth, db } = build({ requireAtLeastOneEmail: true });
	// Sign in for real: Better Auth signs the session cookie, and an unsigned one silently
	// fails to resolve — which would make this whole test pass without ever reaching the gate.
	const signIn = await auth.handler(new Request('http://localhost/auth/sign-in/anonymous', {
		method: 'POST', headers: { 'Content-Type': 'application/json', Origin: 'http://localhost' }, body: '{}'
	}));
	const setCookies = typeof signIn.headers.getSetCookie === 'function'
		? signIn.headers.getSetCookie() : [signIn.headers.get('set-cookie')].filter(Boolean);
	const cookie = setCookies.map((c) => c.split(';')[0]).join('; ');
	const user = db.user[db.user.length - 1];   // anonymous plugin gives it a temp@… email
	const ctx = await auth.$context;
	await ctx.adapter.create({ model: 'passkey', data: {
		userId: user.id, credentialID: 'cred', publicKey: 'pk', counter: 0,
		deviceType: 'multiDevice', backedUp: true, transports: 'internal',
		aaguid: AAGUID, createdAt: new Date(), name: 'cred'
	}});
	await ctx.adapter.create({ model: 'corepass_profile', data: {
		userId: user.id, coreId: COREID,
		o18y: 1, o21y: 1, kyc: 1, kycDoc: null, backedUp: 0, providedTill: null
	}});
	ok(/^temp[-@]/i.test(user.email), `precondition: user carries a temp@ email (${user.email})`);

	// This is the request handle.ts issues on every page load.
	const res = await auth.handler(new Request('http://localhost/auth/get-session', {
		headers: { Origin: 'http://localhost', Cookie: cookie }
	}));
	const body = await res.json().catch(() => null);
	// Proves the gate was actually reached and chose to allow, rather than the session
	// silently failing to resolve.
	ok(body?.user?.id === user.id, 'the session really resolves (so the gate was exercised)');
	ok(db.user.some((u) => u.id === user.id), 'user row SURVIVES a plain GET');
	ok(db.passkey.some((p) => p.userId === user.id), 'passkey SURVIVES a plain GET');
	ok(db.corepass_profile.some((c) => c.userId === user.id), 'corepass_profile SURVIVES a plain GET');

	// The gate must still bite on a mutating request — blocking, not deleting.
	const post = await auth.handler(new Request('http://localhost/auth/update-user', {
		method: 'POST', headers: { 'Content-Type': 'application/json', Origin: 'http://localhost', Cookie: cookie },
		body: JSON.stringify({ name: 'x' })
	}));
	const postBody = await post.json().catch(() => ({}));
	ok(post.status === 403 && postBody?.code === 'EMAIL_REQUIRED',
		`mutating request still blocked with EMAIL_REQUIRED (got ${post.status} ${postBody?.code ?? ''})`);
	ok(db.user.some((u) => u.id === user.id), 'user row SURVIVES the blocked POST too');
}

console.log('\n── E: AAGUID allowlist is enforced ──');
{
	const { auth, db } = build();
	const user = await seedUser(auth, db, { email: 'e@wall.money', passkeys: [] });
	let threw = null;
	try {
		await simulateVerifyRegistration(auth, { userId: user.id, credentialID: 'bad-cred', aaguid: '00000000-0000-0000-0000-000000000000' });
	} catch (err) {
		threw = err;
	}
	ok(threw != null, 'disallowed AAGUID is rejected');
	ok(!db.passkey.some((p) => p.credentialID === 'bad-cred'), 'disallowed credential row is removed');
}

console.log(`\n${failed === 0 ? '\x1b[32mall passed\x1b[0m' : `\x1b[31m${failed} failed\x1b[0m`}`);
process.exit(failed === 0 ? 0 : 1);
