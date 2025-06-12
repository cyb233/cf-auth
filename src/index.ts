interface AuthConfig {
	PASSWORD: string,
	WHITE_LIST: Array<string>,
	ENCRYPTION_KEY: string,
	COOKIE_MAX_AGE: number,
	REFRESH: boolean
}

const COOKIE_NAME = 'cf-auth_token';

async function getLoginHtml(env: Env): Promise<Response> {
	const html = await env.ASSETS.fetch('https://assets.local/login.html');
	return new Response(await html.text(), {
		headers: { 'Content-Type': 'text/html; charset=utf-8' }
	});
}

function getHost(request: Request): string {
	const host = request.headers.get('host') || '';
	return host.split(':')[0].toLowerCase();
}

function getEnvParams(env: Env, host: string): AuthConfig {
	// @ts-ignore
	env[host].WHITE_LIST = env[host].WHITE_LIST || [];
	// @ts-ignore
	env[host].ENCRYPTION_KEY = env[host].ENCRYPTION_KEY || env.ENCRYPTION_KEY;
	// @ts-ignore
	env[host].COOKIE_MAX_AGE = env[host].COOKIE_MAX_AGE || env.COOKIE_MAX_AGE || 3600;
	// @ts-ignore
	env[host].REFRESH = env[host].REFRESH || env.REFRESH || false;
	// @ts-ignore
	return env[host] || {};
}

async function encrypt(text: string, key: CryptoKey): Promise<string> {
	const enc = new TextEncoder().encode(text);
	const iv = crypto.getRandomValues(new Uint8Array(12));
	const ciphertext = await crypto.subtle.encrypt(
		{ name: "AES-GCM", iv },
		key,
		enc
	);
	const buf = new Uint8Array(iv.length + ciphertext.byteLength);
	buf.set(iv, 0);
	buf.set(new Uint8Array(ciphertext), iv.length);
	return btoa(String.fromCharCode(...buf));
}

async function decrypt(token: string, key: CryptoKey): Promise<string | null> {
	try {
		const buf = Uint8Array.from(atob(token), c => c.charCodeAt(0));
		const iv = buf.slice(0, 12);
		const data = buf.slice(12);
		const dec = await crypto.subtle.decrypt(
			{ name: "AES-GCM", iv },
			key,
			data
		);
		return new TextDecoder().decode(dec);
	} catch {
		return null;
	}
}

async function getKey(secret: string): Promise<CryptoKey> {
	const enc = new TextEncoder().encode(secret);
	return crypto.subtle.importKey(
		"raw",
		enc,
		"AES-GCM",
		false,
		["encrypt", "decrypt"]
	);
}

function getCookie(request: Request, name: string): string | null {
	const cookie = request.headers.get('cookie');
	if (!cookie) return null;
	const m = cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
	return m ? decodeURIComponent(m[1]) : null;
}

export default {
	async fetch(request, env, ctx): Promise<Response> {
		const url = new URL(request.url);
		const host = getHost(request);
		const { PASSWORD, WHITE_LIST, ENCRYPTION_KEY, COOKIE_MAX_AGE, REFRESH } = getEnvParams(env, host);

		console.log(`[auth] 请求路径: ${url.pathname}, host: ${host}`);

		// 若无密码，直接通过
		if (!PASSWORD) {
			console.log('[auth] 未配置密码，直接通过');
			return new Response('Hello World!');
		}
		// 检查path白名单，支持普通字符串和正则
		if (WHITE_LIST && WHITE_LIST.length > 0 && WHITE_LIST.some(pattern => new RegExp(pattern).test(url.pathname))) {
			console.log('[auth] 路径在白名单内，直接代理请求');
			return fetch(request);
		}
		console.log('[auth] 路径不在白名单内，进行身份验证');

		// 登录请求
		if (url.pathname === '/api/login' && request.method === 'POST') {
			console.log('[auth] 收到登录请求');
			const { password: inputPwd } = await request.json() as { password: string };
			if (inputPwd === PASSWORD) {
				console.log('[auth] 登录成功');
				const now = Date.now();
				const key = await getKey(ENCRYPTION_KEY);
				const payload = JSON.stringify({ ts: now });
				const token = await encrypt(payload, key);
				return new Response('ok', {
					status: 200,
					headers: {
						'Set-Cookie': `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; Max-Age=${COOKIE_MAX_AGE}`,
						'Content-Type': 'text/plain'
					}
				});
			} else {
				console.log('[auth] 登录失败，密码错误');
				return new Response('Unauthorized', { status: 401 });
			}
		}

		// 检查cookie
		const token = getCookie(request, COOKIE_NAME);
		if (token) {
			console.log('[auth] 检测到cookie，开始校验');
			const key = await getKey(ENCRYPTION_KEY);
			const decrypted = await decrypt(token, key);
			if (decrypted) {
				try {
					const { ts } = JSON.parse(decrypted);
					if (Date.now() - ts < COOKIE_MAX_AGE * 1000) {
						console.log('[auth] cookie有效，代理请求');
						// cookie有效，代理请求
						const resp = await fetch(request);
						// 续期cookie
						const respHeaders = new Headers(resp.headers);
						const newPayload = JSON.stringify({ ts: Date.now() });
						const newToken = await encrypt(newPayload, key);
						respHeaders.append('Set-Cookie', `${COOKIE_NAME}=${encodeURIComponent(newToken)}; Path=/; HttpOnly; Max-Age=${COOKIE_MAX_AGE}`);
						return new Response(resp.body, {
							status: resp.status,
							statusText: resp.statusText,
							headers: respHeaders
						});
					} else {
						console.log('[auth] cookie已过期');
					}
				} catch {
					console.log('[auth] cookie解密或解析失败');
				}
			} else {
				console.log('[auth] cookie解密失败');
			}
			// cookie校验失败，移除cookie
			return new Response(await (await getLoginHtml(env)).text(), {
				status: 200,
				headers: {
					'Set-Cookie': `${COOKIE_NAME}=; Path=/; HttpOnly; Max-Age=0`,
					'Content-Type': 'text/html; charset=utf-8'
				}
			});
		}

		// 未登录，返回登录页
		return getLoginHtml(env);
	},
} satisfies ExportedHandler<Env>;
