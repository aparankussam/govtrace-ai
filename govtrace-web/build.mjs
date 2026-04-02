import { writeFile } from "node:fs/promises";
import path from "node:path";

const normalizeBaseUrl = (value) => {
  const raw = (value ?? "").trim();
  if (!raw) return "/api";
  if (raw === "/") return "";
  return raw.replace(/\/+$/, "");
};

const normalizeSiteUrl = (value) => {
  const raw = (value ?? "").trim();
  if (!raw) return "";

  try {
    return new URL(raw).toString().replace(/\/+$/, "");
  } catch {
    throw new Error(`Invalid GOVTRACE_SITE_URL: ${raw}`);
  }
};

const config = {
  apiBaseUrl: normalizeBaseUrl(process.env.GOVTRACE_API_BASE_URL),
  siteUrl: normalizeSiteUrl(process.env.GOVTRACE_SITE_URL),
};

const output = `window.GOVTRACE_CONFIG = Object.freeze(${JSON.stringify(config, null, 2)});\n`;
const destination = path.join(process.cwd(), "config.js");

await writeFile(destination, output, "utf8");
console.log(`Wrote ${destination}`);
