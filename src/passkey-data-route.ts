/**
 * Serves the enrichment endpoint at exactly /webauthn/data (no base path)
 * and the restore endpoints at /webauthn/restore/*.
 *
 * When the request path matches, rewrites URL to {basePath}/… and forwards to the auth handler.
 */

export const PASSKEY_DATA_PATH = '/webauthn/data';
export const RESTORE_BASE_PATH = '/webauthn/restore';

const DATA_ALLOWED_METHODS = new Set(['HEAD', 'POST']);
const RESTORE_ALLOWED_METHODS = new Set(['POST']);

export type HandlePasskeyDataRouteOptions = {
	/** Better Auth handler (e.g. auth.handler). */
	handler: (request: Request) => Promise<Response>;
	/** Auth base path (e.g. /auth). Rewritten request will use {basePath}/webauthn/…. */
	basePath: string;
};

/**
 * If the request is for /webauthn/data or /webauthn/restore/*, rewrites URL to
 * {basePath}/webauthn/… and forwards to the auth handler. Returns null for other paths.
 */
export async function handlePasskeyDataRoute(
	request: Request,
	options: HandlePasskeyDataRouteOptions
): Promise<Response | null> {
	const pathname = new URL(request.url).pathname.replace(/\/+$/, '') || '/';
	const method = request.method.toUpperCase();

	// /webauthn/data — enrichment (HEAD, POST)
	if (pathname === PASSKEY_DATA_PATH) {
		if (!DATA_ALLOWED_METHODS.has(method)) {
			return new Response(null, { status: 405, headers: { Allow: 'HEAD, POST' } });
		}
		return rewriteAndForward(request, pathname, method, options);
	}

	// /webauthn/restore, /webauthn/restore/init, /webauthn/restore/complete (POST only)
	if (pathname === RESTORE_BASE_PATH || pathname.startsWith(RESTORE_BASE_PATH + '/')) {
		if (!RESTORE_ALLOWED_METHODS.has(method)) {
			return new Response(null, { status: 405, headers: { Allow: 'POST' } });
		}
		return rewriteAndForward(request, pathname, method, options);
	}

	return null;
}

function rewriteAndForward(
	request: Request,
	pathname: string,
	method: string,
	options: HandlePasskeyDataRouteOptions
): Promise<Response> {
	const base = (options.basePath ?? '').replace(/\/+$/, '') || '';
	const rewrittenPath = base ? `${base}${pathname}` : pathname;
	const url = new URL(request.url);
	url.pathname = rewrittenPath;
	const rewrittenRequest = new Request(url, {
		method: request.method,
		headers: request.headers,
		body: method === 'POST' ? request.body : undefined
	});
	return options.handler(rewrittenRequest);
}
