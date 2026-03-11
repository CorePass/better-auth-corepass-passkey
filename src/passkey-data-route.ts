/**
 * Serves the enrichment endpoint at exactly /passkey/data (no base path).
 * When the request path is /passkey/data, rewrites the URL to {basePath}/passkey/data
 * and forwards to the auth handler. Use this in your app's handle/hooks so the plugin
 * owns the route; the app only calls this and returns the response when non-null.
 */

export const PASSKEY_DATA_PATH = '/passkey/data';

export type HandlePasskeyDataRouteOptions = {
	/** Better Auth handler (e.g. auth.handler). */
	handler: (request: Request) => Promise<Response>;
	/** Auth base path (e.g. /auth). Rewritten request will use {basePath}/passkey/data. */
	basePath: string;
};

/**
 * If the request is for GET/HEAD/POST /passkey/data, rewrites URL to {basePath}/passkey/data,
 * calls the auth handler, and returns the response. Otherwise returns null.
 * Use in your SvelteKit (or other) handle: if (await handlePasskeyDataRoute(request, opts)) return that response.
 */
export async function handlePasskeyDataRoute(
	request: Request,
	options: HandlePasskeyDataRouteOptions
): Promise<Response | null> {
	const pathname = new URL(request.url).pathname.replace(/\/+$/, '') || '/';
	if (pathname !== PASSKEY_DATA_PATH) return null;

	const base = (options.basePath ?? '').replace(/\/+$/, '') || '';
	const rewrittenPath = base ? `${base}${PASSKEY_DATA_PATH}` : PASSKEY_DATA_PATH;
	const url = new URL(request.url);
	url.pathname = rewrittenPath;
	const rewrittenRequest = new Request(url, {
		method: request.method,
		headers: request.headers,
		body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined
	});
	return options.handler(rewrittenRequest);
}
