"use strict";

// config.json (ts-admin [자료실 설정]가 생성): { repo, ref, token: 자료실 비밀번호로 암호화한 읽기 전용 토큰 }
const SESSION_KEY = "things-share-token";
const SESSION_MS = 2 * 60 * 60 * 1000; // 비밀번호를 넣은 뒤 2시간이 지나면 다시 묻는다 (탭을 닫아도 다시 묻는다)
const $ = (id) => document.getElementById(id);
let site = null; // config.json
let token = null; // 비밀번호로 푼 토큰
let unlockedAt = 0; // 비밀번호를 넣은 시각 (ms)
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

const sessionExpired = () => token && Date.now() - unlockedAt >= SESSION_MS;

// 2시간이 지났으면 비밀번호 화면으로. 받는 중인 파일은 끊지 않도록 새 요청 때와 화면으로 돌아올 때만 확인한다
function lockIfExpired() {
  if (!sessionExpired()) return false;
  forgetToken();
  location.reload();
  return true;
}
document.addEventListener("visibilitychange", () => { if (!document.hidden) lockIfExpired(); });

async function gh(path) {
  if (lockIfExpired()) throw new Error("접속한 지 2시간이 지나 비밀번호를 다시 확인합니다.");
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

  if (r.note) body.append(el("p", "change", `변경 내용: ${r.note}`));

  const btn = el("button", "download", "다운로드");
  const note = el("p", "card-note");
  btn.onclick = () => download(r, btn, note);
  li.append(body, btn, note);
  if (r.publicSlug) li.append(shareRow(r));

  // 이전 버전: 펼쳐서 받기 (관리자가 보관한 버전만)
  const history = r.history || [];
  if (history.length) {
    const toggle = el("button", "history-toggle", `이전 버전 ${history.length}개`);
    toggle.setAttribute("aria-expanded", "false");
    const list = el("ul", "history");
    list.hidden = true;
    for (const h of history) {
      const item = el("li");
      const info = el("div", "history-info");
      info.append(el("span", "history-version", `v${h.version}`), el("span", "history-date", h.updatedAt || ""));
      if (h.note) info.append(el("span", "history-note", h.note));
      const hb = el("button", "history-download", "받기");
      const hn = el("p", "card-note");
      hb.onclick = () => download(h, hb, hn, "받기");
      item.append(info, hb, hn);
      list.append(item);
    }
    toggle.onclick = () => {
      list.hidden = !list.hidden;
      toggle.setAttribute("aria-expanded", String(!list.hidden));
    };
    li.append(toggle, list);
  }
  return li;
}

// 외부 공유 자료: 비밀번호 없이 받는 안내 페이지(apps/<이름>/) 주소를 보내거나 QR 로 보여 준다
function shareRow(r) {
  const url = new URL(`apps/${r.publicSlug}/`, location.href).href;
  const row = el("div", "share");
  row.append(el("span", "share-label", "외부 공유 링크 · 비밀번호 없이 받음"));
  if (navigator.share) {
    const b = el("button", "share-btn", "공유");
    b.onclick = () => navigator.share({ title: r.title, text: `${r.title} 설치 파일`, url }).catch(() => {});
    row.append(b);
  }
  const copy = el("button", "share-btn", "링크 복사");
  copy.onclick = async () => {
    try {
      await navigator.clipboard.writeText(url);
      copy.textContent = "복사됨";
      setTimeout(() => (copy.textContent = "링크 복사"), 2000);
    } catch {
      prompt("아래 링크를 복사하세요", url);
    }
  };
  const qr = el("button", "share-btn", "QR 보기");
  qr.onclick = () => showQr(r.title, url);
  row.append(copy, qr);
  return row;
}

function showQr(title, url) {
  const qr = qrcode(0, "M");
  qr.addData(url);
  qr.make();
  const src = qr.createDataURL(8, 4);
  $("qr-title").textContent = title;
  $("qr-img").src = src;
  $("qr-img").alt = `${title} 외부 공유 링크 QR 코드`;
  $("qr-url").textContent = url;
  $("qr-save").href = src;
  $("qr-save").download = `${title} QR.gif`;
  $("qr-dialog").showModal();
}

async function download(r, btn, note, label = "다운로드") {
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
    const name = r.fileName || r.path.split("/").pop();
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
    btn.textContent = label;
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
  unlockedAt = Date.now();
  try { sessionStorage.setItem(SESSION_KEY, JSON.stringify({ token, at: unlockedAt })); } catch {}
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
  try {
    const saved = JSON.parse(sessionStorage.getItem(SESSION_KEY));
    if (saved && saved.token && Date.now() - saved.at < SESSION_MS) { token = saved.token; unlockedAt = saved.at; }
  } catch {}
  if (token) return openApp();
  forgetToken(); // 예전 형식이나 만료된 값 지우기
  $("unlock").hidden = false;
  $("pw").focus();
}

["q", "site", "category"].forEach((id) => $(id).addEventListener("input", render));
$("unlock").addEventListener("submit", unlock);
$("qr-close").addEventListener("click", () => $("qr-dialog").close());
start();
