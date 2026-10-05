// Builds dist/chromium, dist/firefox and dist/safari from one source tree.
import { build } from "esbuild";
import { cpSync, mkdirSync, rmSync, writeFileSync } from "node:fs";

const KEY =
  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2jJDTesCwmnIGSvj2HgKyf7bWpFpdIxq94r0rACWQ8xIsJtCZLKWRrIdX6WcKkM0DiQnIfdrnAwjeQJA68Qfefz6VHswDzp2dMIQzoN6HThOUZfvgyQJ1xtINCVSrJlQWplOKvvqwq4H8pwnoA/WNGp40PHmVxs8ihfcUHR2+zeCfs9LTBmIFVdoJg8/QbH9iSnWEs3a766Z2XHmFyfRP9Sx85XvdSSofpyyvtPIp8fQUXuC952WFOk3Q3PX5AeeoDawIhCc8GIwMj4lers9rmjyy2ZYaJguLFPAjQwGvRVdADg39FVUbF4MATRlFdfkYBmR0fX6j6SDDDpaiAGHNwIDAQAB";

const icons = { 16: "icons/16.png", 32: "icons/32.png", 48: "icons/48.png", 128: "icons/128.png" };

const base = {
  manifest_version: 3,
  name: "Keepsake",
  version: "0.1.0",
  description: "Fill passwords and one-time codes from the Keepsake app on your Mac.",
  icons,
  permissions: ["nativeMessaging", "storage", "activeTab"],
  action: { default_popup: "popup.html", default_title: "Keepsake", default_icon: icons },
  content_scripts: [
    { matches: ["http://*/*", "https://*/*"], js: ["content.js"], all_frames: true, run_at: "document_idle" },
  ],
  commands: {
    "fill-login": {
      suggested_key: { default: "Ctrl+Shift+L", mac: "Command+Shift+L" },
      description: "Fill the best login for this page",
    },
  },
};

const targets = {
  chromium: { ...base, key: KEY, minimum_chrome_version: "116", background: { service_worker: "background.js" } },
  firefox: {
    ...base,
    background: { scripts: ["background.js"] },
    browser_specific_settings: { gecko: { id: "keepsake@keepsake.app", strict_min_version: "128.0" } },
  },
  // Packaged by safari/ (Xcode) into the app extension's Resources. A non-persistent background
  // page, as in Apple's own MV3 template: Safari requires it to be non-persistent, and the bundle
  // already runs as a page in Firefox, while Safari's MV3 service workers have been less dependable.
  safari: {
    ...base,
    background: { scripts: ["background.js"], persistent: false },
    browser_specific_settings: { safari: { strict_min_version: "17.0" } },
  },
};

for (const [name, manifest] of Object.entries(targets)) {
  const out = `dist/${name}`;
  rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });
  await build({
    entryPoints: { background: "src/background.ts", content: "src/content.ts", popup: "src/popup/popup.ts" },
    bundle: true,
    format: "iife",
    target: "es2022",
    outdir: out,
    minify: false,
    legalComments: "none",
  });
  cpSync("src/popup/popup.html", `${out}/popup.html`);
  cpSync("src/popup/popup.css", `${out}/popup.css`);
  cpSync("icons", `${out}/icons`, { recursive: true });
  writeFileSync(`${out}/manifest.json`, JSON.stringify(manifest, null, 2));
  console.log(`built ${out}`);
}
