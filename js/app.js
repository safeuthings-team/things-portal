"use strict";

// config.json (ts-admin [포털 배포]가 생성): { repo, ref, token: 자료실 비밀번호로 암호화한 읽기 전용 토큰 }
const SESSION_KEY = "things-share-token";
const $ = (id) => document.getElementById(id);
let site = null; // config.json
let token = null; // 비밀번호로 푼 토큰
let manifest = null;

const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

// ts-admin Protect-Token 과 같은 방식: PBKDF2-SHA256 → 마스터키 → HMAC("enc"/"mac") 로 키 분리,
// AES-256-CBC 복호화 전에 HMAC-SHA256(iv||ct) 검증. 비밀번호가 틀리면 null.
async function decryptToken(enc, password) {
  const subtle = crypto.subtle;
  const base = await subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const master = await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: fromB64(enc.salt), iterations: enc.iter }, base, 256);
  const kdf = await subtle.importKey("raw", master, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sub = async (label) => subtle.sign("HMAC", kdf, new TextEncoder().encode(label));
  const encKey = await subtle.importKey("raw", await sub("enc"), "AES-CBC", false, ["decrypt"]);
  const macKey = await subtle.importKey("raw", await sub("mac"), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  const iv = fromB64(enc.iv);
  const ct = fromB64(enc.ct);
  const signed = new Uint8Array(iv.length + ct.length);
  signed.set(iv);
  signed.set(ct, iv.length);
  if (!(await subtle.verify("HMAC", macKey, fromB64(enc.mac), signed))) return null;
  return new TextDecoder().decode(await subtle.decrypt({ name: "AES-CBC", iv }, encKey, ct));
}

function forgetToken() {
  token = null;
  try { sessionStorage.removeItem(SESSION_KEY); } catch {}
}

async function gh(path) {
  const url = `https://api.github.com/repos/${site.repo}/contents/` +
    path.split("/").map(encodeURIComponent).join("/") + `?ref=${site.ref}`;
  let res;
  try {
    res = await fetch(url, {
      headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github.raw+json" },
      cache: "no-store",
    });
  } catch {
    throw new Error("네트워크에 연결할 수 없습니다. 인터넷 연결을 확인하세요.");
  }
  if (res.status === 401) {
    forgetToken();
    throw new Error("자료실 인증이 만료되었습니다. 관리자에게 문의하세요.");
  }
  if (res.status === 403 || res.status === 429) throw new Error("요청이 많습니다. 잠시 후 다시 시도하세요.");
  if (!res.ok) throw new Error(`자료를 가져오지 못했습니다. (오류 ${res.status})`);
  return res;
}

const matches = (r, site, category, q) =>
  (!site || r.siteIds.length === 0 || r.siteIds.includes(site)) &&
  (!category || r.category === category) &&
  (!q || [r.title, r.description, ...(r.tags || [])].join(" ").toLowerCase().includes(q));

function el(tag, className, text) {
  const e = document.createElement(tag);
  if (className) e.className = className;
  if (text !== undefined) e.textContent = text;
  return e;
}

function showStatus(message, retry) {
  const box = $("status");
  box.replaceChildren(el("span", "", message));
  if (retry) {
    const btn = el("button", "retry", "다시 시도");
    btn.onclick = retry;
    box.append(btn);
  }
}

function siteLabel(r) {
  if (r.siteIds.length === 0) return "공통";
  const names = Object.fromEntries(manifest.sites.map((s) => [s.id, s.name]));
  return r.siteIds.map((id) => names[id] || id).join(", ");
}

function render() {
  const site = $("site").value;
  const category = $("category").value;
  const q = $("q").value.trim().toLowerCase();
  const items = manifest.resources.filter((r) => matches(r, site, category, q));

  $("list").replaceChildren(...items.map(card));
  showStatus(items.length ? `자료 ${items.length}건` : "조건에 맞는 자료가 없습니다.");
}

function card(r) {
  const li = el("li", "card");
  const body = el("div", "card-body");
  body.append(el("h2", "", r.title));
  if (r.description) body.append(el("p", "desc", r.description));
  const meta = el("p", "meta");
  [r.fileType, `v${r.version}`, siteLabel(r), r.updatedAt].filter(Boolean).forEach((text, i) => {
    if (i) meta.append(" · ");
    meta.append(el("span", "", text));
  });
  body.append(meta);

  const btn = el("button", "download", "다운로드");
  const note = el("p", "card-note");
  btn.onclick = () => download(r, btn, note);
  li.append(body, btn, note);
  return li;
}

async function download(r, btn, note) {
  btn.disabled = true;
  note.replaceChildren();
  note.classList.remove("error");
  try {
    const res = await gh(r.path);
    const total = Number(res.headers.get("Content-Length")) || 0;
    const reader = res.body.getReader();
    const chunks = [];
    let received = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      received += value.length;
      btn.textContent = total
        ? `${Math.round((received / total) * 100)}%`
        : `${(received / 1048576).toFixed(1)}MB`;
    }
    // 받는 데 시간이 걸리면 브라우저가 자동 다운로드로 보고 막을 수 있다
    // (Chrome '여러 파일 다운로드' 차단 등). 그래서 직접 눌러 저장할 링크도 함께 보여 준다.
    const name = r.path.split("/").pop();
    const a = el("a", "save-link", `다운로드가 시작되지 않았다면 여기를 눌러 저장 (${name})`);
    a.href = URL.createObjectURL(new Blob(chunks));
    a.download = name;
    note.replaceChildren(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); note.replaceChildren(); }, 10 * 60000);
  } catch (e) {
    note.textContent = e.message;
    note.classList.add("error");
  } finally {
    btn.disabled = false;
    btn.textContent = "다운로드";
  }
}

async function load() {
  showStatus("자료 목록을 불러오는 중…");
  try {
    manifest = await (await gh("manifest.json")).json();
  } catch (e) {
    showStatus(e.message, load);
    return;
  }
  const siteSelect = $("site");
  siteSelect.replaceChildren(new Option("전체 현장", ""), ...manifest.sites.map((s) => new Option(s.name, s.id)));
  render();
}

function openApp() {
  $("unlock").hidden = true;
  $("app").hidden = false;
  load();
}

async function unlock(e) {
  e.preventDefault();
  const btn = $("unlock-btn");
  btn.disabled = true;
  $("unlock-msg").textContent = "확인 중…";
  try {
    token = await decryptToken(site.token, $("pw").value);
  } catch {
    token = null;
  }
  btn.disabled = false;
  if (!token) {
    $("unlock-msg").textContent = "비밀번호가 틀렸습니다.";
    $("pw").select();
    return;
  }
  $("unlock-msg").textContent = "";
  try { sessionStorage.setItem(SESSION_KEY, token); } catch {}
  openApp();
}

async function start() {
  try {
    const res = await fetch(`config.json?v=${Date.now()}`, { cache: "no-store" });
    if (!res.ok) throw new Error();
    site = await res.json();
  } catch {
    showStatus("자료실 설정(config.json)을 불러오지 못했습니다. 관리자에게 문의하세요.", start);
    return;
  }
  showStatus("");
  try { token = sessionStorage.getItem(SESSION_KEY); } catch {}
  if (token) return openApp();
  $("unlock").hidden = false;
  $("pw").focus();
}

["q", "site", "category"].forEach((id) => $(id).addEventListener("input", render));
$("unlock").addEventListener("submit", unlock);
start();
