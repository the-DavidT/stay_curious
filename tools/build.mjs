#!/usr/bin/env node
// Encrypts source_photos/ into assets/ for the password-protected gallery.
//
// Usage:
//   node tools/build.mjs --password "your-password"
//
// Source layout (NOT published, gitignored):
//   source_photos/first-day/*.jpg|png
//   source_photos/last-day/*.jpg|png
//
// Output (published):
//   assets/manifest.enc        salt(16) | iv(12) | AES-256-GCM ciphertext of manifest JSON
//   assets/img_NNN.enc         iv(12) | AES-256-GCM ciphertext of the image bytes
//
// The password never touches the repo. Wrong password fails GCM authentication
// in the browser, so the photos cannot be recovered from the published files.

import { createCipheriv, pbkdf2Sync, randomBytes } from "node:crypto";
import { readdirSync, readFileSync, writeFileSync, rmSync, mkdirSync } from "node:fs";
import { join, dirname, extname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SRC = join(ROOT, "source_photos");
const OUT = join(ROOT, "assets");
const PBKDF2_ITERATIONS = 310000;

const SECTIONS = [
  { dir: "first-day", title: "היום הראשון", subtitle: "איפה שהכל התחיל" },
  { dir: "last-day", title: "היום האחרון", subtitle: "קו הסיום" },
];

const argIdx = process.argv.indexOf("--password");
const password = argIdx > -1 ? process.argv[argIdx + 1] : null;
if (!password) {
  console.error('Missing password. Run: node tools/build.mjs --password "..."');
  process.exit(1);
}

const salt = randomBytes(16);
const key = pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, 32, "sha256");

function encrypt(plaintext) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  return { iv, ct };
}

rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });

// Private site text lives in gitignored source_photos/site.json:
//   { "heroTitle": "..." }
let siteConfig = {};
try {
  siteConfig = JSON.parse(readFileSync(join(SRC, "site.json"), "utf8"));
} catch {
  console.warn("No source_photos/site.json found; hero title will be empty.");
}

let counter = 0;
const manifest = { hero: { title: siteConfig.heroTitle || "" }, sections: [] };

for (const section of SECTIONS) {
  const dir = join(SRC, section.dir);
  let files = [];
  try {
    files = readdirSync(dir)
      .filter((f) => [".jpg", ".jpeg", ".png", ".webp"].includes(extname(f).toLowerCase()))
      .sort();
  } catch {
    console.warn(`Skipping missing folder: ${dir}`);
  }
  const images = [];
  for (const file of files) {
    const name = `img_${String(counter++).padStart(3, "0")}.enc`;
    const { iv, ct } = encrypt(readFileSync(join(dir, file)));
    writeFileSync(join(OUT, name), Buffer.concat([iv, ct]));
    images.push({ file: name, type: extname(file).toLowerCase() === ".png" ? "image/png" : "image/jpeg" });
    console.log(`${section.dir}/${file} -> assets/${name}`);
  }
  manifest.sections.push({ title: section.title, subtitle: section.subtitle, images });
}

const { iv, ct } = encrypt(Buffer.from(JSON.stringify(manifest), "utf8"));
writeFileSync(join(OUT, "manifest.enc"), Buffer.concat([salt, iv, ct]));
console.log(`assets/manifest.enc written (${counter} images, PBKDF2 ${PBKDF2_ITERATIONS} iterations)`);
