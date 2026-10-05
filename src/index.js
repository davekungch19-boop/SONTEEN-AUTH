const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET,POST,DELETE,OPTIONS",
      "access-control-allow-headers": "content-type,x-admin-token"
    }
  });

function cors(request) {
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "access-control-allow-origin": "*",
        "access-control-allow-methods": "GET,POST,DELETE,OPTIONS",
        "access-control-allow-headers": "content-type,x-admin-token"
      }
    });
  }
  return null;
}

function makeKey() {
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  const hex = [...bytes].map(b => b.toString(16).padStart(2, "0")).join("").toUpperCase();
  return `ST-${hex.slice(0,4)}-${hex.slice(4,8)}-${hex.slice(8,12)}`;
}

function adminOK(request, env) {
  const supplied = request.headers.get("x-admin-token") || "";
  return supplied && env.ADMIN_TOKEN && supplied === env.ADMIN_TOKEN;
}

async function verifyKey(request, env) {
  let body;
  try { body = await request.json(); } catch { return json({success:false,message:"Invalid JSON"},400); }
  const key = String(body.key || "").trim().toUpperCase();
  if (!key) return json({success:false,message:"Key is required"},400);

  const row = await env.DB.prepare(
    "SELECT key,status,expires_at,max_devices FROM licenses WHERE key = ?"
  ).bind(key).first();

  if (!row) return json({success:false,message:"Invalid key"},401);
  if (row.status !== "active") return json({success:false,message:"Key is disabled"},403);

  if (row.expires_at) {
    const expiry = new Date(row.expires_at);
    if (Number.isNaN(expiry.getTime()) || expiry <= new Date()) {
      return json({success:false,message:"Key has expired"},403);
    }
  }

  return json({
    success: true,
    message: "Key is valid",
    expiresAt: row.expires_at,
    maxDevices: row.max_devices
  });
}

async function listKeys(env) {
  const result = await env.DB.prepare(
    "SELECT id,key,status,expires_at,max_devices,created_at,note FROM licenses ORDER BY id DESC"
  ).all();
  return json({success:true,items:result.results || []});
}

async function createKey(request, env) {
  let body = {};
  try { body = await request.json(); } catch {}
  const key = (body.key ? String(body.key).trim().toUpperCase() : makeKey());
  const status = body.status === "disabled" ? "disabled" : "active";
  const expiresAt = body.expiresAt ? new Date(body.expiresAt).toISOString() : null;
  const maxDevices = Math.max(1, Math.min(100, Number(body.maxDevices || 1)));
  const note = String(body.note || "").slice(0, 200);

  try {
    await env.DB.prepare(
      "INSERT INTO licenses (key,status,expires_at,max_devices,created_at,note) VALUES (?,?,?,?,?,?)"
    ).bind(key,status,expiresAt,maxDevices,new Date().toISOString(),note).run();
  } catch {
    return json({success:false,message:"Key already exists or data is invalid"},409);
  }
  return json({success:true,key});
}

async function deleteKey(request, env, id) {
  await env.DB.prepare("DELETE FROM licenses WHERE id = ?").bind(id).run();
  return json({success:true});
}

async function updateKey(request, env, id) {
  let body;
  try { body = await request.json(); } catch { return json({success:false,message:"Invalid JSON"},400); }
  const sets = [];
  const vals = [];
  if (body.status === "active" || body.status === "disabled") {
    sets.push("status=?");
    vals.push(body.status);
  }
  if ("expiresAt" in body) {
    sets.push("expires_at=?");
    vals.push(body.expiresAt ? new Date(body.expiresAt).toISOString() : null);
  }
  if (!sets.length) return json({success:false,message:"Nothing to update"},400);
  await env.DB.prepare(
    `UPDATE licenses SET ${sets.join(", ")} WHERE id=?`
  ).bind(...vals, id).run();
  return json({success:true});
}

export default {
  async fetch(request, env) {
    const preflight = cors(request);
    if (preflight) return preflight;

    const url = new URL(request.url);

    if (url.pathname === "/auth/verify" && request.method === "POST") {
      return verifyKey(request, env);
    }

    if (url.pathname.startsWith("/api/admin/")) {
      if (!adminOK(request, env)) return json({success:false,message:"Unauthorized"},401);

      if (url.pathname === "/api/admin/keys" && request.method === "GET")
        return listKeys(env);

      if (url.pathname === "/api/admin/keys" && request.method === "POST")
        return createKey(request, env);

      const match = url.pathname.match(/^\/api\/admin\/keys\/(\d+)$/);
      if (match) {
        const id = Number(match[1]);
        if (request.method === "DELETE") return deleteKey(request, env, id);
        if (request.method === "PATCH") return updateKey(request, env, id);
      }

      return json({success:false,message:"Not found"},404);
    }

    if (url.pathname === "/admin" || url.pathname === "/admin/") {
      return new Response(await (await fetch(new URL("/admin/index.html", request.url))).text(), {
        headers: {"content-type":"text/html; charset=utf-8"}
      });
    }

    return new Response("SONTEEN AUTH API", {
      headers: {"content-type":"text/plain; charset=utf-8"}
    });
  }
};
