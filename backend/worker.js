const SESSION_SECONDS = 60 * 60 * 8;
const COOKIE_NAME = "__Host-shady_session";
const MAX_QUERY_LENGTH = 120;
const MAX_RESULTS = 100;

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
      "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
      ...extraHeaders,
    },
  });
}

function corsHeaders(request, env) {
  const origin = request.headers.get("Origin");
  const allowed = (env.ALLOWED_ORIGIN || "").replace(/\/$/, "");
  if (!origin || !allowed || origin.replace(/\/$/, "") !== allowed) return {};
  return {
    "access-control-allow-origin": allowed,
    "access-control-allow-credentials": "true",
    "vary": "Origin",
  };
}

function b64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function fromB64url(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(normalized + "=".repeat((4 - normalized.length % 4) % 4)), c => c.charCodeAt(0));
}
async function hmac(secret, value) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), {name:"HMAC", hash:"SHA-256"}, false, ["sign","verify"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value)));
}
async function signSession(payload, secret) {
  const body = b64url(new TextEncoder().encode(JSON.stringify(payload)));
  return body + "." + b64url(await hmac(secret, body));
}
async function verifySession(token, secret) {
  if (!token || !token.includes(".")) return null;
  const [body, signature, extra] = token.split(".");
  if (!body || !signature || extra) return null;
  const expected = await hmac(secret, body);
  const actual = fromB64url(signature);
  if (actual.length !== expected.length || !actual.every((b, i) => b === expected[i])) return null;
  try {
    const payload = JSON.parse(new TextDecoder().decode(fromB64url(body)));
    if (!payload.sub || !payload.exp || payload.exp <= Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}
async function sha256Hex(value) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
  return [...digest].map(b => b.toString(16).padStart(2, "0")).join("");
}
function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  for (const part of header.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return rest.join("=");
  }
  return "";
}
function sessionCookie(value, maxAge = SESSION_SECONDS) {
  return `${COOKIE_NAME}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Strict`;
}
function clearCookie() {
  return `${COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`;
}
function normalizeQuery(value) {
  return String(value || "").trim().replace(/\s+/g, " ");
}
function safeCustomer(row) {
  return {
    name: row.name || "",
    area: row.area || "",
    phone1: row.phone1 || "",
    phone2: row.phone2 || "",
    phone3: row.phone3 || "",
    street: row.street || "",
    description: row.description || "",
    building: row.building || "",
    floor: row.floor || "",
    apartment: row.apartment || "",
    notes: row.notes || "",
  };
}

async function requireUser(request, env) {
  const token = getCookie(request, COOKIE_NAME);
  const payload = await verifySession(token, env.SESSION_SECRET);
  if (!payload) return null;
  const sessionHash = await sha256Hex(token);
  const session = await env.DB.prepare(
    "SELECT u.id, u.username, u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id_hash=? AND s.user_id=? AND s.expires_at>? AND u.is_active=1"
  ).bind(sessionHash, payload.sub, Math.floor(Date.now()/1000)).first();
  return session || null;
}

export default {
  async fetch(request, env) {
    const headers = corsHeaders(request, env);
    const url = new URL(request.url);
    if (request.method === "OPTIONS") {
      return new Response(null, {status: 204, headers: {
        ...headers,
        "access-control-allow-methods": "GET, POST, OPTIONS",
        "access-control-allow-headers": "content-type",
        "access-control-max-age": "600",
      }});
    }
    if (!env.DB || !env.SESSION_SECRET || env.SESSION_SECRET.length < 32) {
      return json({error:"Server configuration incomplete"}, 503, headers);
    }

    if (url.pathname === "/api/health" && request.method === "GET") {
      return json({ok:true}, 200, headers);
    }

    if (url.pathname === "/api/auth/login" && request.method === "POST") {
      let body;
      try { body = await request.json(); } catch { return json({error:"بيانات غير صحيحة"}, 400, headers); }
      const username = String(body.username || "").trim();
      const password = String(body.password || "");
      if (!username || !password || username.length > 100 || password.length > 256) {
        return json({error:"اسم المستخدم أو كلمة المرور غير صحيحة"}, 400, headers);
      }
      // Basic per-IP + username throttle. Add Cloudflare edge rate limiting as a second layer.
      const ip = request.headers.get("CF-Connecting-IP") || "unknown";
      const bucketKey = await sha256Hex(ip + String.fromCharCode(10) + username.toLowerCase());
      const nowForThrottle = Math.floor(Date.now()/1000);
      const bucket = await env.DB.prepare("SELECT window_start, attempts FROM login_attempts WHERE bucket_key=?").bind(bucketKey).first();
      if (bucket && bucket.window_start > nowForThrottle - 900 && bucket.attempts >= 10) {
        return json({error:"محاولات كثيرة. جرّب بعد 15 دقيقة."}, 429, headers);
      }
      if (!bucket || bucket.window_start <= nowForThrottle - 900) {
        await env.DB.prepare("INSERT INTO login_attempts(bucket_key,window_start,attempts) VALUES(?,?,1) ON CONFLICT(bucket_key) DO UPDATE SET window_start=excluded.window_start, attempts=1").bind(bucketKey,nowForThrottle).run();
      } else {
        await env.DB.prepare("UPDATE login_attempts SET attempts=attempts+1 WHERE bucket_key=?").bind(bucketKey).run();
      }
      // Account records and password hashes live only in D1, never in front-end code.
      const user = await env.DB.prepare(
        "SELECT id, username, password_hash, role FROM users WHERE username=? COLLATE NOCASE AND is_active=1"
      ).bind(username).first();
      // PBKDF2 hash format: pbkdf2-sha256$iterations$saltBase64Url$hashBase64Url
      let valid = false;
      if (user && user.password_hash) {
        try {
          const [scheme, iterationsText, saltText, hashText] = user.password_hash.split("$");
          const iterations = Number(iterationsText);
          if (scheme === "pbkdf2-sha256" && iterations >= 100000 && iterations <= 1000000 && saltText && hashText) {
            const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
            const derived = new Uint8Array(await crypto.subtle.deriveBits({name:"PBKDF2", hash:"SHA-256", salt:fromB64url(saltText), iterations}, key, 256));
            const expected = fromB64url(hashText);
            valid = derived.length === expected.length && derived.every((b,i)=>b===expected[i]);
          }
        } catch { valid = false; }
      }
      if (!valid) return json({error:"اسم المستخدم أو كلمة المرور غير صحيحة"}, 401, headers);
      const now = Math.floor(Date.now()/1000);
      const token = await signSession({sub:user.id, exp:now+SESSION_SECONDS}, env.SESSION_SECRET);
      const idHash = await sha256Hex(token);
      await env.DB.prepare("DELETE FROM sessions WHERE expires_at<=?").bind(now).run();
      await env.DB.prepare("INSERT INTO sessions(id_hash,user_id,expires_at) VALUES(?,?,?)").bind(idHash,user.id,now+SESSION_SECONDS).run();
      return json({ok:true,user:{username:user.username,role:user.role}}, 200, {
        ...headers,
        "set-cookie": sessionCookie(token),
      });
    }

    if (url.pathname === "/api/auth/logout" && request.method === "POST") {
      const token = getCookie(request, COOKIE_NAME);
      if (token) await env.DB.prepare("DELETE FROM sessions WHERE id_hash=?").bind(await sha256Hex(token)).run();
      return json({ok:true}, 200, {...headers, "set-cookie":clearCookie()});
    }

    if (url.pathname === "/api/auth/me" && request.method === "GET") {
      const user = await requireUser(request, env);
      if (!user) return json({error:"غير مسجل الدخول"}, 401, headers);
      return json({ok:true,user:{username:user.username,role:user.role}}, 200, headers);
    }

    if (url.pathname === "/api/search" && request.method === "GET") {
      const user = await requireUser(request, env);
      if (!user) return json({error:"غير مسجل الدخول"}, 401, headers);
      const q = normalizeQuery(url.searchParams.get("q"));
      const area = normalizeQuery(url.searchParams.get("area"));
      if (q.length > MAX_QUERY_LENGTH || area.length > 120) return json({error:"البحث أطول من المسموح"}, 400, headers);
      if (!q && !area) return json({results:[],count:0,limit:MAX_RESULTS}, 200, headers);
      const clauses = [];
      const params = [];
      if (q) {
        // Current app supports substring matching across search_blob.
        // Benchmark this against the imported data; use FTS/trigram strategy if scans are slow.
        for (const token of q.split(" ").filter(Boolean).slice(0, 8)) {
          clauses.push("search_blob LIKE ? ESCAPE '!'");
          const escaped = token.split("").map(ch => (ch === "!" || ch === "%" || ch === "_") ? "!" + ch : ch).join("");
          params.push("%" + escaped + "%");
        }
      }
      if (area) { clauses.push("area = ?"); params.push(area); }
      const sql = "SELECT name, area, phone1, phone2, phone3, street, description, building, floor, apartment, notes FROM customers WHERE " + clauses.join(" AND ") + " LIMIT ?";
      params.push(MAX_RESULTS);
      try {
        const result = await env.DB.prepare(sql).bind(...params).all();
        const results = (result.results || []).map(safeCustomer);
        // Record only non-sensitive usage metadata: no query text, phone, customer ID, or area value.
        await env.DB.prepare(
          "INSERT INTO search_events(user_id,used_query,used_area,results_count) VALUES(?,?,?,?)"
        ).bind(user.id, q ? 1 : 0, area ? 1 : 0, results.length).run();
        // Keep the audit table bounded; old events are automatically removed after 30 days.
        await env.DB.prepare("DELETE FROM search_events WHERE created_at < datetime('now','-30 days')").run();
        return json({results,count:results.length,limit:MAX_RESULTS}, 200, headers);
      } catch (error) {
        // Avoid returning SQL or customer data in error messages.
        console.error("search query failed");
        return json({error:"تعذر تنفيذ البحث حاليًا"}, 500, headers);
      }
    }

    if (url.pathname === "/api/admin/dashboard" && request.method === "GET") {
      const user = await requireUser(request, env);
      if (!user) return json({error:"غير مسجل الدخول"}, 401, headers);
      if (user.role !== "admin") return json({error:"غير مسموح"}, 403, headers);
      try {
        const totals = await env.DB.prepare(
          "SELECT COUNT(*) AS total_records, COUNT(DISTINCT CASE WHEN area IS NOT NULL AND TRIM(area)<>'' THEN area END) AS total_areas FROM customers"
        ).first();
        const metadataRows = await env.DB.prepare(
          "SELECT key,value FROM app_metadata WHERE key IN ('last_data_update','data_status')"
        ).all();
        const metadata = Object.fromEntries((metadataRows.results || []).map(row => [row.key, row.value]));
        const recent = await env.DB.prepare(
          "SELECT e.created_at,u.username,e.used_query,e.used_area,e.results_count FROM search_events e JOIN users u ON u.id=e.user_id ORDER BY e.id DESC LIMIT 20"
        ).all();
        const usage = await env.DB.prepare(
          "SELECT COUNT(*) AS searches, COALESCE(SUM(used_query),0) AS text_filter_uses, COALESCE(SUM(used_area),0) AS area_filter_uses FROM search_events WHERE created_at >= datetime('now','-7 days')"
        ).first();
        const last = await env.DB.prepare(
          "SELECT MAX(created_at) AS last_search_at FROM search_events"
        ).first();
        return json({
          ok:true,
          totals:{records:Number(totals?.total_records || 0),areas:Number(totals?.total_areas || 0)},
          data:{lastUpdated:metadata.last_data_update || null,status:metadata.data_status || "لم يتم تسجيل حالة الاستيراد"},
          usage:{searches7d:Number(usage?.searches || 0),textFilterUses:Number(usage?.text_filter_uses || 0),areaFilterUses:Number(usage?.area_filter_uses || 0),lastSearchAt:last?.last_search_at || null},
          recent:(recent.results || []).map(row=>({createdAt:row.created_at,username:row.username,usedQuery:Boolean(row.used_query),usedArea:Boolean(row.used_area),resultsCount:Number(row.results_count || 0)}))
        },200,headers);
      } catch (error) {
        console.error("admin dashboard query failed");
        return json({error:"تعذر تحميل الإحصائيات. تأكد من تطبيق schema.sql بعد أخذ نسخة احتياطية."},500,headers);
      }
    }

    if (url.pathname.startsWith("/api/admin/")) {
      const user = await requireUser(request, env);
      if (!user) return json({error:"غير مسجل الدخول"}, 401, headers);
      if (user.role !== "admin") return json({error:"غير مسموح"}, 403, headers);
      return json({error:"مسار الإدارة لم يُنفّذ بعد"}, 501, headers);
    }

    return json({error:"Not found"}, 404, headers);
  }
};
