/**
 * Proves the case-tolerant lookup does NOT alter the default restore path.
 *
 *  1. Normal restore (DB holds uppercase, as enrichment always writes): exactly ONE
 *     corepass_profile lookup, with the uppercase value — identical to the old behaviour.
 *  2. Genuinely unknown Core ID: still 404 CORE_ID_NOT_FOUND, challenge still reverts to
 *     'pending'. The fallbacks only add lookups on a path that was already a guaranteed miss.
 *  3. If a canonical uppercase row and a hand-written lowercase row both exist, the uppercase
 *     one wins — a fallback can never steal a canonical account.
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
const OTHER  = 'CB7712A2B0F3C4D5E6F708192A3B4C5D6E7F8091A2B3';
const hex = (b) => Buffer.from(b).toString('hex');
const nowSec = () => Math.floor(Date.now() / 1000);

async function run({ rows, signWith }) {
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
	const ctx = await auth.$context;

	const owners = {};
	for (const [label, storedCoreId] of Object.entries(rows)) {
		const user = await ctx.internalAdapter.createUser({
			email: `${label}@wall.money`, emailVerified: false, isAnonymous: true,
			name: label, createdAt: new Date(), updatedAt: new Date()
		});
		await ctx.adapter.create({ model: 'corepass_profile', data: {
			userId: user.id, coreId: storedCoreId, o18y: 1, o21y: 1, kyc: 1,
			kycDoc: null, backedUp: 0, providedTill: null
		}});
		owners[label] = user.id;
	}

	// count corepass_profile lookups made during the restore call
	const realFindOne = ctx.adapter.findOne.bind(ctx.adapter);
	const probes = [];
	ctx.adapter.findOne = async (arg) => {
		if (arg.model === 'corepass_profile') {
			const v = arg.where?.find((w) => w.field === 'coreId')?.value;
			if (v !== undefined) probes.push(v);
		}
		return realFindOne(arg);
	};

	const ch = await ctx.adapter.create({ model: 'restore_challenge', data: {
		userId: null, status: 'pending', expiresAt: nowSec() + 300
	}});
	const priv = ed448.utils.randomSecretKey ? ed448.utils.randomSecretKey() : ed448.utils.randomPrivateKey();
	const pub = ed448.getPublicKey(priv);
	const payload = { coreId: signWith, restoreId: ch.id, timestamp: Date.now() * 1000 };
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
	return { status: res.status, body, probes, owners, challenge };
}

console.log('\n── 1. default restore: DB uppercase (what enrichment writes) ──');
{
	const r = await run({ rows: { canonical: COREID }, signWith: COREID });
	console.log(`   status=${r.status}  profile lookups=${r.probes.length} -> ${JSON.stringify(r.probes)}`);
	ok(r.status === 200, 'succeeds');
	ok(r.probes.length === 1, `exactly ONE lookup, as before (got ${r.probes.length})`);
	ok(r.probes[0] === COREID, 'and it is the uppercase value — query is unchanged');
	ok(r.challenge?.userId === r.owners.canonical, 'resolves to the right account');
}

console.log('\n── 2. genuinely unknown Core ID: still a clean miss ──');
{
	const r = await run({ rows: { someoneElse: OTHER }, signWith: COREID });
	console.log(`   status=${r.status} ${JSON.stringify(r.body)}  lookups=${r.probes.length}`);
	ok(r.status === 404 && r.body?.code === 'CORE_ID_NOT_FOUND', 'still 404 CORE_ID_NOT_FOUND');
	ok(r.challenge?.status === 'pending', "challenge still reverts to 'pending'");
	ok(r.probes.length === 3, `fallbacks only run on the already-failing path (got ${r.probes.length})`);
}

console.log('\n── 3. canonical uppercase row AND a hand-written lowercase row both exist ──');
{
	const r = await run({ rows: { canonical: COREID, handWritten: COREID.toLowerCase() }, signWith: COREID });
	console.log(`   status=${r.status}  lookups=${r.probes.length}`);
	ok(r.status === 200, 'succeeds');
	ok(r.challenge?.userId === r.owners.canonical, 'uppercase (canonical) wins — a fallback cannot steal an account');
	ok(r.probes.length === 1, 'stops at the first match');
}

console.log(`\n${failed === 0 ? '\x1b[32mall passed\x1b[0m' : `\x1b[31m${failed} failed\x1b[0m`}`);
process.exit(failed === 0 ? 0 : 1);
