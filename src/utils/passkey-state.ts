/**
 * Helpers for "require passkey for access" flow: check if user has any passkey and if a request is allowed before first passkey.
 */

export type AdapterLike = {
	findOne: (arg: {
		model: string;
		where: { field: string; value: unknown }[];
	}) => Promise<unknown>;
};

const DEFAULT_ALLOW_ROUTES: string[] = [];
const DEFAULT_ALLOW_METHODS = ['GET', 'HEAD', 'OPTIONS'];
const DEFAULT_PASSKEY_REGISTRATION_ROUTES = [
	'/passkey/generate-register-options',
	'/passkey/verify-registration'
];

export type PasskeyGateOptions = {
	allowRoutesBeforePasskey?: string[];
	allowMethodsBeforePasskey?: string[];
	allowPasskeyRegistrationRoutes?: string[];
};

/**
 * Returns true if the user has at least one passkey.
 */
export async function hasAnyPasskey(
	adapter: AdapterLike,
	userId: string
): Promise<boolean> {
	const one = await adapter.findOne({
		model: 'passkey',
		where: [{ field: 'userId', value: userId }]
	});
	return one != null;
}

/**
 * Returns true if the given path and method are allowed when the user has no passkey yet
 * (registration, enrichment, and optionally safe methods).
 */
export function isAllowedBeforePasskey(
	pathname: string,
	method: string,
	options: PasskeyGateOptions = {}
): boolean {
	const allowRoutes = options.allowRoutesBeforePasskey ?? DEFAULT_ALLOW_ROUTES;
	const allowMethods = options.allowMethodsBeforePasskey ?? DEFAULT_ALLOW_METHODS;
	const allowRegistration = options.allowPasskeyRegistrationRoutes ?? DEFAULT_PASSKEY_REGISTRATION_ROUTES;

	const upperMethod = method.toUpperCase();
	if (allowMethods.includes(upperMethod)) {
		return true;
	}
	const path = pathname.replace(/\/+$/, '') || '/';
	const allowedPaths = [...allowRoutes, ...allowRegistration];
	return allowedPaths.some((p) => path === p || path.startsWith(p + '/'));
}
