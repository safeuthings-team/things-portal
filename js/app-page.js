"use strict";

// 외부 공유 안내 페이지 (ts-admin 이 apps/<이름>/index.html 로 만든다)
const ua = navigator.userAgent;
const here = location.href.split("#")[0];

// 메신저 앱 안 브라우저는 APK 다운로드를 막는 경우가 많다.
// 카카오톡은 기본 브라우저로 다시 열 수 있고, 나머지는 안내만 보여 준다.
if (/KAKAOTALK/i.test(ua)) location.href = "kakaotalk://web/openExternal?url=" + encodeURIComponent(here);
if (/KAKAOTALK|NAVER\(inapp|Line\/|Instagram|FBAN|FBAV|DaumApps|everytimeApp/i.test(ua)) document.getElementById("inapp").hidden = false;

// PC 에서 열었을 때 휴대폰으로 찍을 QR (터치 기기에서는 CSS 로 숨김)
const box = document.getElementById("qr");
if (box && typeof qrcode === "function") {
  const qr = qrcode(0, "M");
  qr.addData(here);
  qr.make();
  box.innerHTML = qr.createSvgTag({ cellSize: 6, margin: 2, alt: "이 페이지 QR 코드" });
}
