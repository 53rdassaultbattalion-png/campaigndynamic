/**
 * Cloudflare Pages Function — Supabase API Proxy
 *
 * Sits between your frontend and Supabase. The browser NEVER sees your
 * SUPABASE_URL or SUPABASE_ANON_KEY — they only exist as Cloudflare
 * environment variables on the server side.
 *
 * Routes:
 *   POST /api/query        — proxies a Supabase REST read/write
 *   POST /api/admin/login  — validates admin password using SHA-256 hash
 *
 * Environment variables to set in Cloudflare Pages dashboard:
 *   SUPABASE_URL           — e.g. https://xxxx.supabase.co
 *   SUPABASE_ANON_KEY      — your anon/public key
 *   ADMIN_PASSWORD_HASH    — SHA-256 hex hash of your admin password
 *                            Generate at: https://emn178.github.io/online-tools/sha256.html
 *                            or run:  echo -n "yourpassword" | sha256sum
 */

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, apikey, Prefer',
};

export async function onRequest(context) {
  const { request, env } = context;

  // Handle CORS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS });
  }

  const url = new URL(request.url);
  const path = url.pathname;

  // ── Admin login — password check via hash comparison ──
  if (path === '/api/admin/login' && request.method === 'POST') {
    return handleAdminLogin(request, env);
  }

  // ── Supabase proxy — all other /api/* routes ──
  if (path.startsWith('/api/')) {
    return handleSupabaseProxy(request, env, path);
  }

  return new Response('Not found', { status: 404 });
}

// ─────────────────────────────────────────────
// Admin password check (hash comparison)
// ─────────────────────────────────────────────
async function handleAdminLogin(request, env) {
  let body;
  try { body = await request.json(); }
  catch { return jsonResponse({ ok: false, error: 'Invalid JSON' }, 400); }

  const { password } = body;
  if (!password) return jsonResponse({ ok: false, error: 'No password provided' }, 400);

  const storedHash = env.ADMIN_PASSWORD_HASH;
  if (!storedHash) {
    // Fallback: if no hash set yet, allow 'changeme' so first-run works
    // Remove this fallback once you set ADMIN_PASSWORD_HASH in Cloudflare
    const isDefault = password === 'changeme';
    return jsonResponse({ ok: isDefault });
  }

  // Hash the submitted password and compare
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

  const match = hashHex === storedHash.toLowerCase();
  return jsonResponse({ ok: match });
}

// ─────────────────────────────────────────────
// Supabase REST proxy
// ─────────────────────────────────────────────
async function handleSupabaseProxy(request, env, path) {
  const SUPABASE_URL = env.SUPABASE_URL;
  const SUPABASE_KEY = env.SUPABASE_ANON_KEY;

  if (!SUPABASE_URL || !SUPABASE_KEY) {
    return jsonResponse({
      error: 'Server not configured. Set SUPABASE_URL and SUPABASE_ANON_KEY in Cloudflare Pages environment variables.'
    }, 500);
  }

  // Strip /api prefix and forward to Supabase REST
  // e.g. /api/rest/v1/planets → https://xxx.supabase.co/rest/v1/planets
  const supabasePath = path.replace(/^\/api/, '');
  const url = new URL(request.url);
  const targetUrl = `${SUPABASE_URL}${supabasePath}${url.search}`;

  // Clone the request, inject Supabase auth headers
  const proxyHeaders = new Headers(request.headers);
  proxyHeaders.set('apikey', SUPABASE_KEY);
  proxyHeaders.set('Authorization', `Bearer ${SUPABASE_KEY}`);
  proxyHeaders.delete('host'); // Cloudflare adds the correct host automatically

  let proxyBody = undefined;
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    proxyBody = await request.text();
  }

  const proxyRequest = new Request(targetUrl, {
    method: request.method,
    headers: proxyHeaders,
    body: proxyBody,
  });

  try {
    const response = await fetch(proxyRequest);
    const responseBody = await response.text();

    return new Response(responseBody, {
      status: response.status,
      headers: {
        ...CORS,
        'Content-Type': response.headers.get('Content-Type') || 'application/json',
        'Content-Range': response.headers.get('Content-Range') || '',
      },
    });
  } catch (err) {
    return jsonResponse({ error: 'Proxy fetch failed: ' + err.message }, 502);
  }
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}
