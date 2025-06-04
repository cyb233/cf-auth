/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Bind resources to your worker in `wrangler.jsonc`. After adding bindings, a type definition for the
 * `Env` object can be regenerated with `npm run cf-typegen`.
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

const COOKIE_NAME = 'auth_token';
const COOKIE_MAX_AGE = 60 * 60; // 1小时

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

function getPasswordKey(host: string): string {
	return `${host}`;
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
		const passwordKey = getPasswordKey(host);
		//@ts-ignore
		const password = env[passwordKey];
		const encKey = env.ENCRYPTION_KEY;

		// 若无密码，直接通过
		if (!password) {
			return new Response('Hello World!');
		}

		// 登录请求
		if (url.pathname === '/api/login' && request.method === 'POST') {
			const { password: inputPwd } = await request.json() as { password: string };
			if (inputPwd === password) {
				const now = Date.now();
				const key = await getKey(encKey);
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
				return new Response('Unauthorized', { status: 401 });
			}
		}

		// 检查cookie
		const token = getCookie(request, COOKIE_NAME);
		if (token) {
			const key = await getKey(encKey);
			const decrypted = await decrypt(token, key);
			if (decrypted) {
				try {
					const { ts } = JSON.parse(decrypted);
					if (Date.now() - ts < COOKIE_MAX_AGE * 1000) {
						// cookie有效，代理请求
						return fetch(request);
					}
				} catch { }
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
