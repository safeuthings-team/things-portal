"use strict";

// config.json (ts-admin [자료실 설정]가 생성): { repo, ref, token: 자료실 비밀번호로 암호화한 읽기 전용 토큰 }
const SESSION_KEY = "things-share-token";
const SESSION_MS = 2 * 60 * 60 * 1000; // 비밀번호를 넣은 뒤 2시간이 지나면 다시 묻는다 (탭을 닫아도 다시 묻는다)
const LOCK_KEY = "things-share-lock"; // 2시간이 지나 다시 묻는 이유를 새로고침 뒤에 보여 주려고 남긴다
const FILTER_KEY = "things-share-filters"; // 이 탭의 검색·필터 (다시 열어도 그대로)
const SITE_KEY = "things-share-site"; // 마지막으로 고른 현장 (다음 방문에도)
const KINDS = { app: "앱", manual: "매뉴얼", guide: "퀵 가이드", other: "기타" };
const MANY_SITES = 10; // PC: 현장이 이보다 많으면 가로 단추 대신 드롭다운
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
  try { sessionStorage.setItem(LOCK_KEY, "expired"); } catch {}
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
  if (!res.ok) throw new Error(`자료를 가져오지 못했습니다. 잠시 후 다시 시도하고, 계속되면 자료실 관리자에게 알려 주세요. (오류 ${res.status})`);
  return res;
}

// 검색 대상: 자료명·설명·태그 + 현장 이름·파일 이름·형식·버전·변경 내용. 띄어 쓴 낱말은 모두 들어 있어야 한다
const haystack = (r) => (r.hay ??= [r.title, r.description, siteLabel(r), r.fileName, r.fileType, r.version, r.note, ...(r.tags || [])].join(" ").toLowerCase());
const matches = (r, site, category, q) =>
  (!site || r.siteIds.length === 0 || r.siteIds.includes(site)) &&
  (!category || r.category === category) &&
  (!q || q.split(/\s+/).every((word) => haystack(r).includes(word)));

function el(tag, className, text) {
  const e = document.createElement(tag);
  if (className) e.className = className;
  if (text !== undefined) e.textContent = text;
  return e;
}

// 글(#status, 화면 낭독기가 읽는 곳)과 단추(#status-action)를 따로 둔다: 함께 두면 글자를 칠 때마다 단추 이름까지 다시 읽힌다
function showStatus(message, action, label = "다시 시도") {
  $("status").textContent = message;
  const btn = action ? el("button", "retry", label) : null;
  if (btn) btn.onclick = action;
  $("status-action").replaceChildren(...(btn ? [btn] : []));
}

function icon(name) {
  const i = el("span", `icon i-${name}`);
  i.setAttribute("aria-hidden", "true");
  return i;
}

// 주소에도 남긴다 (?site=…&category=…&q=…): 그 주소를 보내면 받은 사람도 같은 조건으로 열린다
function saveFilters() {
  const f = { q: $("q").value.trim(), site: $("site").value, category: $("category").value, sort: $("sort").value };
  try { sessionStorage.setItem(FILTER_KEY, JSON.stringify(f)); localStorage.setItem(SITE_KEY, f.site); } catch {}
  if (f.sort === "new") delete f.sort;
  const qs = new URLSearchParams(Object.entries(f).filter(([, v]) => v)).toString();
  history.replaceState(null, "", qs ? `?${qs}` : location.pathname);
}

// 순서: 주소에 조건이 있으면 그것, 없으면 이 탭에서 보던 조건, 그것도 없으면 지난번에 고른 현장
function restoreFilters() {
  let f = {};
  const url = Object.fromEntries(new URLSearchParams(location.search));
  try { f = JSON.parse(sessionStorage.getItem(FILTER_KEY)) || { site: localStorage.getItem(SITE_KEY) || "" }; } catch {}
  if (["q", "site", "category", "sort"].some((k) => k in url)) f = url;
  const pick = (id, v) => { if (v && [...$(id).options].some((o) => o.value === v)) $(id).value = v; };
  pick("site", f.site);
  pick("category", f.category);
  pick("sort", f.sort);
  if (f.q) $("q").value = f.q;
}

function resetFilters() {
  $("q").value = "";
  $("site").value = "";
  $("category").value = "";
  saveFilters();
  render();
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

  // 날짜가 같은 자료는 관리자가 넣은 순서 그대로 (sort 는 순서를 유지한다)
  if ($("sort").value === "name") items.sort((a, b) => a.title.localeCompare(b.title, "ko"));
  else items.sort((a, b) => (b.updatedAt || "").localeCompare(a.updatedAt || ""));

  $("list").replaceChildren(...items.map(card));
  // 조건을 걸었으면 몇 건 중 몇 건인지 알려 주고, 언제든 한 번에 풀 수 있게 한다
  const filtered = site || category || q;
  if (!items.length) showStatus("조건에 맞는 자료가 없습니다.", filtered ? resetFilters : null, "필터 초기화");
  else if (filtered) showStatus(`전체 ${manifest.resources.length}건 중 ${items.length}건`, resetFilters, "필터 초기화");
  else showStatus(`자료 ${items.length}건`);
  renderFacets(site, category, q);
}

// PC 필터: 현장·종류를 가로로 늘어놓은 단추(개수 포함). 누르면 드롭다운 값을 바꾼 것과 같다 (휴대폰은 드롭다운만 보임)
function renderFacets(site, category, q) {
  const group = (title, selectId, options, current) => {
    const box = el("div", "facet-group");
    const list = el("div", "facet-list");
    box.setAttribute("role", "group");
    box.setAttribute("aria-label", title);
    box.append(el("h2", "facet-title", title), list);
    for (const [value, label, count] of options) {
      const b = el("button", "facet");
      b.type = "button";
      b.dataset.key = `${selectId}:${value}`;
      b.setAttribute("aria-pressed", String(value === current));
      if (!value) b.dataset.all = "";   // '모든 …' 은 걸러 낸 것이 아니므로 강조색을 쓰지 않는다
      if (!count && value !== current) b.dataset.empty = "";
      b.append(el("span", "", label), el("span", "facet-count", String(count)));
      b.onclick = () => { $(selectId).value = value; onFilter(); };
      list.append(b);
    }
    return box;
  };
  const n = (s, c) => manifest.resources.filter((r) => matches(r, s, c, q)).length;
  // 자료가 하나도 없는 종류는 고를 일이 없으니 내놓지 않는다 (지금 골라 둔 것은 남긴다)
  const kinds = [["", "모든 종류", n(site, "")], ...Object.entries(KINDS).filter(([v]) => v === category || manifest.resources.some((r) => r.category === v)).map(([v, l]) => [v, l, n(site, v)])];
  const sites = [["", "모든 현장", n("", category)], ...manifest.sites.map((s) => [s.id, s.name, n(s.id, category)])];
  // 현장이 먼저: 자료 대부분이 한 현장 것이라 사용자는 자기 현장부터 고른다.
  // 현장이 많으면 단추가 여러 줄을 차지해 목록을 밀어내므로 드롭다운을 쓴다 (CSS .many-sites)
  const many = manifest.sites.length > MANY_SITES;
  $("app").classList.toggle("many-sites", many);
  // 단추를 새로 만들어도 키보드 위치(포커스)는 누른 단추에 그대로 둔다
  const focused = document.activeElement && document.activeElement.dataset ? document.activeElement.dataset.key : null;
  $("facets").replaceChildren(...(manifest.sites.length && !many ? [group("현장", "site", sites, site)] : []), group("종류", "category", kinds, category));
  if (focused) [...$("facets").querySelectorAll(".facet")].find((b) => b.dataset.key === focused)?.focus();
}

// 목록은 바로 바꾸고, 저장은 입력이 멈춘 뒤에
let typing = 0;
function onFilter() {
  render();
  clearTimeout(typing);
  typing = setTimeout(saveFilters, 300);
}

function card(r) {
  const li = el("li", "card");
  const body = el("div", "card-body");
  const head = el("div", "card-title");
  const title = el("div", "title-wrap");
  title.append(el("h2", "", r.title));
  if (r.publicSlug) {
    const pub = el("span", "pub", "공개");
    pub.title = "공개 링크가 있는 자료입니다. 그 링크로는 비밀번호 없이 누구나 받을 수 있습니다.";
    title.append(pub);
  }
  head.append(el("span", "kind", KINDS[r.category] || "기타"), title);
  body.append(head);
  if (r.description) body.append(el("p", "desc", r.description));
  // 휴대폰은 한 줄("현장 · APK · v1.4.2 · 날짜"), PC 는 표의 칸으로 나뉜다 (구분점은 CSS 가 그림).
  // 현장이 먼저: 제목이 같은 자료를 가르는 것이 현장이다. 형식·버전·날짜는 한 칸에 모은다
  const meta = el("p", "meta");
  const when = el("span", "m-when");
  [["m-type", r.fileType], ["m-ver", `v${r.version}`], ["m-date", r.updatedAt]].forEach(([cls, text]) => {
    if (text) when.append(el("span", cls, text));
  });
  meta.append(el("span", "m-site", siteLabel(r)), when);
  body.append(meta);

  if (r.note) body.append(el("p", "change", `변경 내용: ${r.note}`));

  // 화면 낭독기·단추 목록에서 어느 자료의 단추인지 알 수 있게 이름에 자료명과 현장을 넣는다
  const what = `${r.title} (${siteLabel(r)})`;
  const btn = el("button", "download");
  btn.append(icon("down"), el("span", "", "다운로드"));
  btn.setAttribute("aria-label", `${what} 다운로드`);
  const note = el("p", "card-note");
  note.setAttribute("aria-live", "polite");
  btn.onclick = () => download(r, btn, note);
  li.append(body, btn, note);
  if (r.publicSlug) li.append(...shareRow(r, what));

  // 이전 버전: 펼쳐서 받기 (관리자가 보관한 버전만)
  const history = r.history || [];
  if (history.length) {
    const toggle = el("button", "history-toggle");
    toggle.append(el("span", "", `이전 버전 ${history.length}개`), icon("chev"));
    toggle.setAttribute("aria-expanded", "false");
    const list = el("ul", "history");
    list.hidden = true;
    for (const h of history) {
      const item = el("li");
      const info = el("div", "history-info");
      info.append(el("span", "history-version", `v${h.version}`), el("span", "history-date", h.updatedAt || ""));
      if (h.note) info.append(el("span", "history-note", h.note));
      const hb = el("button", "history-download", "다운로드");
      hb.setAttribute("aria-label", `v${h.version} 다운로드`);
      const hn = el("p", "card-note");
      hn.setAttribute("aria-live", "polite");
      hb.onclick = () => download(h, hb, hn);
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

// 공개 링크 자료: 비밀번호 없이 받는 안내 페이지(apps/<이름>/) 주소를 보내거나 QR 로 보여 준다.
// 줄마다 설명과 단추 셋을 늘어놓으면 목록이 그것으로 덮이므로 [공유] 하나로 접어 두고, 눌렀을 때만 펼친다
function shareRow(r, what) {
  const url = new URL(`apps/${r.publicSlug}/`, location.href).href;
  const toggle = el("button", "share-toggle");
  toggle.append(el("span", "", "공유"), icon("chev"));
  toggle.setAttribute("aria-label", `${what} 공개 링크 공유`);
  toggle.setAttribute("aria-expanded", "false");
  const row = el("div", "share");
  row.hidden = true;
  toggle.onclick = () => {
    row.hidden = !row.hidden;
    toggle.setAttribute("aria-expanded", String(!row.hidden));
  };
  const label = el("span", "share-label");
  label.append(el("b", "", "공개 링크"), " · 비밀번호 없이 누구나 받을 수 있습니다");
  row.append(label);
  // 기기의 공유 창은 휴대폰에서만 (PC 에서는 [링크 복사]와 같은 일을 한다)
  if (navigator.share && matchMedia("(pointer: coarse)").matches) {
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
  return [toggle, row];
}

function showQr(title, url) {
  const qr = qrcode(0, "M");
  qr.addData(url);
  qr.make();
  const src = qr.createDataURL(8, 4);
  $("qr-title").textContent = title;
  $("qr-img").src = src;
  $("qr-img").alt = `${title} 공개 링크 QR 코드`;
  $("qr-url").textContent = url;
  $("qr-save").href = src;
  $("qr-save").download = `${title} QR.gif`;
  $("qr-dialog").showModal();
}

async function download(r, btn, note) {
  const original = [...btn.childNodes];
  btn.disabled = true;
  btn.setAttribute("aria-busy", "true");
  btn.textContent = "받는 중…";
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
        ? `받는 중 ${Math.round((received / total) * 100)}%`
        : `받는 중 ${(received / 1048576).toFixed(1)}MB`;
    }
    // 받는 데 시간이 걸리면 브라우저가 자동 다운로드로 보고 막을 수 있다
    // (Chrome '여러 파일 다운로드' 차단 등). 그래서 직접 눌러 저장할 링크도 함께 보여 준다.
    const name = r.fileName || r.path.split("/").pop();
    const a = el("a", "save-link", "저장되지 않았다면 다시 저장");
    a.href = URL.createObjectURL(new Blob(chunks));
    a.download = name;
    note.replaceChildren(el("span", "", `받았습니다: ${name}`), a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); note.replaceChildren(); }, 10 * 60000);
  } catch (e) {
    // 무엇이 안 됐는지와 함께 바로 다시 해 볼 단추를 그 자리에 둔다
    const retry = el("button", "note-retry", "다시 시도");
    retry.onclick = () => download(r, btn, note);
    note.replaceChildren(icon("alert"), el("span", "", e.message), retry);
    note.classList.add("error");
  } finally {
    btn.disabled = false;
    btn.removeAttribute("aria-busy");
    btn.replaceChildren(...original);
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
  siteSelect.replaceChildren(new Option("모든 현장", ""), ...manifest.sites.map((s) => new Option(s.name, s.id)));
  for (const o of $("category").options) o.hidden = !!o.value && !manifest.resources.some((r) => r.category === o.value);   // 자료가 없는 종류는 숨김
  $("sort").hidden = false;
  restoreFilters();
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
  const msg = $("unlock-msg");
  btn.disabled = true;
  msg.className = "unlock-msg";
  msg.textContent = "확인 중…";
  try {
    token = await decryptToken(site.token, $("pw").value);
  } catch {
    token = null;
  }
  btn.disabled = false;
  if (!token) {
    msg.className = "unlock-msg error";
    msg.textContent = "비밀번호가 틀렸습니다. 다시 입력하세요.";
    $("pw").select();
    return;
  }
  msg.textContent = "";
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
  try {
    if (sessionStorage.getItem(LOCK_KEY)) $("unlock-msg").textContent = "접속한 지 2시간이 지나 비밀번호를 다시 확인합니다. 보던 검색 조건은 그대로 남아 있습니다.";
    sessionStorage.removeItem(LOCK_KEY);
  } catch {}
  $("unlock").hidden = false;
  if (matchMedia("(pointer: fine)").matches) $("pw").focus(); // 휴대폰에서는 키보드가 바로 올라오지 않게
}

["q", "site", "category", "sort"].forEach((id) => $(id).addEventListener("input", onFilter));
// 키보드: / 로 검색 칸, 검색 칸에서 Enter 로 첫 자료, Esc 로 검색어 지우기
document.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && e.target === $("q") && !e.isComposing) { e.preventDefault(); $("list").querySelector(".download")?.focus(); }
  else if (e.key === "/" && !$("app").hidden && !document.querySelector("dialog[open]") && !/^(INPUT|SELECT|TEXTAREA)$/.test(document.activeElement.tagName)) { e.preventDefault(); $("q").focus(); $("q").select(); }
  else if (e.key === "Escape" && e.target === $("q") && $("q").value) { e.preventDefault(); $("q").value = ""; onFilter(); }
});
$("unlock").addEventListener("submit", unlock);
$("qr-close").addEventListener("click", () => $("qr-dialog").close());
$("qr-dialog").addEventListener("click", (e) => { if (e.target === e.currentTarget) e.currentTarget.close(); }); // 바깥 누르면 닫기
start();
