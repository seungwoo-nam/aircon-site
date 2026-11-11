// 전자랜드 안동점 에어컨 가격표 — 직원용 공유 저장 기능 (클라우드플레어)
// 매니저 목록, 관리자 비밀번호, 매니저별 견적을 클라우드플레어 KV 저장 공간(이름: KV)에 보관합니다.

// 암호화된 홈페이지 안에만 들어 있는 직원 열쇠의 지문(sha256)
const STAFF_HASH = "1a164e05fc31cb815533c71f50ae87b6f7bc3090d3f4ad95db6327c344d13c44";

const WX = { t: 0, data: null };
const enc = new TextEncoder();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });
const sha = async (s) => hex(await crypto.subtle.digest("SHA-256", enc.encode(String(s))));
const rand = (n) => hex(crypto.getRandomValues(new Uint8Array(n)));
const clean = (s, n) => String(s ?? "").replace(/[\u0000-\u001f]/g, "").trim().slice(0, n);
const okId = (s) => /^[A-Za-z0-9_-]{1,40}$/.test(String(s || ""));
async function hashPin(pin, salt) {
  const k = await crypto.subtle.importKey("raw", enc.encode(String(pin)), "PBKDF2", false, ["deriveBits"]);
  return hex(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: enc.encode(salt), iterations: 100000 }, k, 256));
}
function same(a, b) { if (a.length !== b.length) return false; let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0; }

function store(KV) {
  return {
    get: (k, o) => KV.get(k, o && o.type === "json" ? { type: "json" } : undefined),
    setJSON: (k, v) => KV.put(k, JSON.stringify(v)),
    delete: (k) => KV.delete(k),
    async list({ prefix }) { const out = []; let cursor; do { const r = await KV.list({ prefix, cursor }); r.keys.forEach((k) => out.push({ key: k.name })); cursor = r.list_complete ? null : r.cursor; } while (cursor); return { blobs: out }; },
  };
}

async function checkPin(st, pin) {
  const cfg = await st.get("cfg/admin", { type: "json" });
  if (!cfg) return { ok: false, setup: true };
  const now = Date.now();
  if (cfg.lockUntil && cfg.lockUntil > now) return { ok: false, locked: Math.ceil((cfg.lockUntil - now) / 60000) };
  if (same(await hashPin(pin, cfg.salt), cfg.hash)) {
    if (cfg.fails) { cfg.fails = 0; cfg.lockUntil = 0; await st.setJSON("cfg/admin", cfg); }
    return { ok: true, cfg };
  }
  cfg.fails = (cfg.fails || 0) + 1;
  if (cfg.fails >= 5) { cfg.lockUntil = now + 10 * 60000; cfg.fails = 0; }
  await st.setJSON("cfg/admin", cfg);
  return { ok: false };
}
const pinErr = (r) => r.setup ? J({ error: "관리자 비밀번호가 아직 없어요.", setup: true }, 409)
  : r.locked ? J({ error: `비밀번호를 여러 번 틀려서 ${r.locked}분 동안 잠겼어요.` }, 429)
  : J({ error: "관리자 비밀번호가 맞지 않아요." }, 403);

async function canAll(st, as) {
  if (!okId(as)) return false;
  const list = (await st.get("cfg/managers", { type: "json" })) || [];
  return list.some((m) => m.id === as && m.all);
}
function cleanMgrs(list) {
  if (!Array.isArray(list)) return null;
  const out = [];
  for (const m of list.slice(0, 60)) {
    const name = clean(m && m.name, 20); if (!name) continue;
    const id = okId(m.id) ? m.id : "m" + rand(5);
    out.push({ id, name, tel: clean(m.tel, 20), all: !!m.all });
  }
  return out;
}

export async function onRequest({ request: req, env }) {
  const key = req.headers.get("x-key") || "";
  if (!key || (await sha(key)) !== STAFF_HASH) return J({ error: "권한이 없어요." }, 401);
  if (!env.KV) return J({ error: "저장 공간(KV)이 아직 연결되지 않았어요." }, 503);
  const st = store(env.KV);
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/api\/?/, "").replace(/\/$/, "");
  const m = req.method;
  let body = {};
  if (m === "POST" || m === "PUT") { try { body = await req.json(); } catch { body = {}; } }
  try {
    if (path === "time" && m === "GET") {
      const t0 = Date.now(); let naver = null;
      try { const r = await fetch("https://www.naver.com/", { method: "HEAD", signal: AbortSignal.timeout(2500) }); const d = r.headers.get("date"); if (d) naver = Date.parse(d); } catch {}
      const t1 = Date.now();
      if (naver && !isNaN(naver)) {
        const diff = (t0 + t1) / 2 - naver;
        if (diff > -1500 && diff < 2500) return J({ now: Date.now(), src: "naver", diff: Math.round(diff) });
        return J({ now: naver + 500 + (Date.now() - t1), src: "naver-raw", diff: Math.round(diff) });
      }
      return J({ now: Date.now(), src: "server" });
    }
    if (path === "weather" && m === "GET") {
      if (WX.data && Date.now() - WX.t < 10 * 60000) return J(WX.data);
      const u = "https://api.open-meteo.com/v1/forecast?latitude=36.5684&longitude=128.7294&current=temperature_2m,apparent_temperature,relative_humidity_2m,weather_code,wind_speed_10m,is_day&daily=temperature_2m_max,temperature_2m_min,precipitation_probability_max,weather_code&timezone=Asia%2FSeoul&forecast_days=2&wind_speed_unit=ms";
      const r = await fetch(u, { signal: AbortSignal.timeout(5000) });
      if (!r.ok) return J({ error: "날씨를 불러오지 못했어요." }, 502);
      const w = await r.json();
      WX.data = { place: "경북 안동", at: w.current && w.current.time, current: w.current, daily: w.daily, source: "Open-Meteo" }; WX.t = Date.now();
      return J(WX.data);
    }
    if (path === "managers" && m === "GET") {
      const [list, cfg] = await Promise.all([st.get("cfg/managers", { type: "json" }), st.get("cfg/admin")]);
      return J({ managers: list || [], adminSet: !!cfg });
    }
    if (path === "admin/setup" && m === "POST") {
      if (await st.get("cfg/admin")) return J({ error: "관리자 비밀번호가 이미 있어요." }, 409);
      const pin = String(body.pin || "");
      if (!/^\d{4,12}$/.test(pin)) return J({ error: "숫자 4~12자리로 정해 주세요." }, 400);
      const salt = rand(16);
      await st.setJSON("cfg/admin", { salt, hash: await hashPin(pin, salt), fails: 0, lockUntil: 0 });
      return J({ ok: true });
    }
    if (path === "admin/login" && m === "POST") {
      const r = await checkPin(st, body.pin); if (!r.ok) return pinErr(r);
      return J({ ok: true });
    }
    if (path === "admin/pin" && m === "POST") {
      const r = await checkPin(st, body.pin); if (!r.ok) return pinErr(r);
      const np = String(body.newPin || "");
      if (!/^\d{4,12}$/.test(np)) return J({ error: "새 비밀번호는 숫자 4~12자리로 정해 주세요." }, 400);
      const salt = rand(16);
      await st.setJSON("cfg/admin", { salt, hash: await hashPin(np, salt), fails: 0, lockUntil: 0 });
      return J({ ok: true });
    }
    if (path === "managers" && m === "PUT") {
      const r = await checkPin(st, body.pin); if (!r.ok) return pinErr(r);
      const list = cleanMgrs(body.managers); if (!list) return J({ error: "목록이 올바르지 않아요." }, 400);
      await st.setJSON("cfg/managers", list);
      return J({ ok: true, managers: list });
    }
    // 이사용: 저장 공간이 비어 있을 때만 한 번 받아들입니다.
    if (path === "import" && m === "POST") {
      const cur = await st.get("cfg/managers", { type: "json" });
      if (cur && cur.length) return J({ error: "이미 매니저가 등록되어 있어요." }, 409);
      const list = cleanMgrs(body.managers) || [];
      let n = 0;
      for (const q of (Array.isArray(body.quotes) ? body.quotes : []).slice(0, 500)) {
        if (!okId(q.id) || !okId(q.mgrId)) continue;
        await st.setJSON(`q/${q.mgrId}/${q.id}`, q); n++;
      }
      await st.setJSON("cfg/managers", list);
      return J({ ok: true, managers: list.length, quotes: n });
    }
    if (path === "quotes" && m === "GET") {
      const mg = url.searchParams.get("mgr") || "all", as = url.searchParams.get("as") || "";
      if (mg !== "all" && !okId(mg)) return J({ error: "매니저가 올바르지 않아요." }, 400);
      if (mg !== as && !(await canAll(st, as))) return J({ error: "다른 매니저의 견적은 볼 수 없어요." }, 403);
      const { blobs } = await st.list({ prefix: mg === "all" ? "q/" : `q/${mg}/` });
      const recs = (await Promise.all(blobs.slice(0, 400).map((b) => st.get(b.key, { type: "json" }).catch(() => null)))).filter(Boolean);
      recs.sort((a, b) => String(b.savedAt).localeCompare(String(a.savedAt)));
      return J({ quotes: recs.slice(0, 300) });
    }
    if (path === "quotes" && m === "PUT") {
      const rec = body.rec || {};
      if (!okId(rec.id) || !okId(rec.mgrId)) return J({ error: "견적 정보가 올바르지 않아요." }, 400);
      const txt = JSON.stringify(rec); if (txt.length > 400000) return J({ error: "견적이 너무 커요." }, 413);
      rec.savedAt = new Date().toISOString();
      if (okId(body.prevMgr) && body.prevMgr !== rec.mgrId) await st.delete(`q/${body.prevMgr}/${rec.id}`);
      await st.setJSON(`q/${rec.mgrId}/${rec.id}`, rec);
      return J({ ok: true, savedAt: rec.savedAt });
    }
    if (path === "quotes" && m === "DELETE") {
      const mg = url.searchParams.get("mgr"), id = url.searchParams.get("id"), as = url.searchParams.get("as") || "";
      if (!okId(mg) || !okId(id)) return J({ error: "견적 정보가 올바르지 않아요." }, 400);
      if (mg !== as && !(await canAll(st, as))) return J({ error: "다른 매니저의 견적은 지울 수 없어요." }, 403);
      await st.delete(`q/${mg}/${id}`);
      return J({ ok: true });
    }
    return J({ error: "없는 기능이에요." }, 404);
  } catch (e) {
    return J({ error: "저장 공간에 연결하지 못했어요. 잠시 후 다시 해 주세요." }, 500);
  }
}
