/**
 * Serves the enrichment endpoint at exactly /passkey/data (no base path).
 * Only HEAD (verify if active) and POST (receive data from application for verification) are allowed.
 * When the request path is /passkey/data and method is HEAD or POST, rewrites URL to {basePath}/passkey/data
 * and forwards to the auth handler. GET returns 405 Method Not Allowed.
 */

export const PASSKEY_DATA_PATH = '/passkey/data';

const ALLOWED_METHODS = new Set(['HEAD', 'POST']);

export type HandlePasskeyDataRouteOptions = {
	/** Better Auth handler (e.g. auth.handler). */
	handler: (request: Request) => Promise<Response>;
	/** Auth base path (e.g. /auth). Rewritten request will use {basePath}/passkey/data. */
	basePath: string;
};

/**
 * If the request is for HEAD or POST /passkey/data, rewrites URL to {basePath}/passkey/data,
 * calls the auth handler, and returns the response. GET returns 405. Other paths return null.
 */
export async function handlePasskeyDataRoute(
	request: Request,
	options: HandlePasskeyDataRouteOptions
): Promise<Response | null> {
	const pathname = new URL(request.url).pathname.replace(/\/+$/, '') || '/';
	if (pathname !== PASSKEY_DATA_PATH) return null;

	const method = request.method.toUpperCase();
	if (!ALLOWED_METHODS.has(method)) {
		return new Response(null, { status: 405, headers: { Allow: 'HEAD, POST' } });
	}

	const base = (options.basePath ?? '').replace(/\/+$/, '') || '';
	const rewrittenPath = base ? `${base}${PASSKEY_DATA_PATH}` : PASSKEY_DATA_PATH;
	const url = new URL(request.url);
	url.pathname = rewrittenPath;
	const rewrittenRequest = new Request(url, {
		method: request.method,
		headers: request.headers,
		body: method === 'POST' ? request.body : undefined
	});
	return options.handler(rewrittenRequest);
}
