import type { Config, Context } from "@netlify/functions";

/**
 * Standalone lead-verification endpoint. Given a business's website URL, it:
 *  - checks whether the site actually responds (live/dead)
 *  - scans the real page for phone numbers and emails actually printed there
 *  - if the homepage has neither, tries /contact and /about as a fallback
 *
 * Every fetch in this function shares ONE overall time budget (see
 * FUNCTION_BUDGET_MS) so adding sub-page checks can never push total
 * execution past Netlify's 10-second function cap, no matter how slow any
 * individual page is to respond.
 */

interface VerifyResult {
  url: string;
  live: boolean;
  blocked: boolean; // true = the response looks like a bot/firewall challenge (Cloudflare, WAF, etc.), not a genuinely broken site
  statusCode: number | null;
  phonesFoundOnPage: string[];
  emailsFoundOnPage: string[];
  checkedSubpage: string | null;
  error: string | null;
}

const FUNCTION_BUDGET_MS = 8500; // leaves ~1.5s headroom under Netlify's 10s cap
const deadline = Date.now() + FUNCTION_BUDGET_MS;
const remainingMs = () => Math.max(0, deadline - Date.now());

function getVisibleText(html: string): string {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<[^>]+>/g, " ");
}

function extractJsonLdContacts(html: string): { phones: string[]; emails: string[] } {
  const phones: string[] = [];
  const emails: string[] = [];
  const blocks = html.match(/<script[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi) || [];

  function walk(node: any) {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) {
      for (const item of node) walk(item);
      return;
    }
    if (typeof node.telephone === "string") phones.push(node.telephone);
    if (typeof node.email === "string") emails.push(node.email);
    for (const key of Object.keys(node)) {
      const val = node[key];
      if (val && typeof val === "object") walk(val);
    }
  }

  for (const block of blocks) {
    const inner = block.replace(/^<script[^>]*>/i, "").replace(/<\/script>$/i, "").trim();
    try {
      walk(JSON.parse(inner));
    } catch {
      // Malformed/partial JSON-LD is common — skip rather than fail the request.
    }
  }
  return { phones, emails };
}

function extractPhones(html: string): string[] {
  const seenDigits = new Map<string, string>();

  function addIfNew(raw: string) {
    const digits = raw.replace(/\D/g, "");
    if (digits.length < 10 || digits.length > 15) return;
    const key = digits.length === 11 && digits.startsWith("1") ? digits.slice(1) : digits;
    if (!seenDigits.has(key)) seenDigits.set(key, raw.trim());
  }

  const jsonLd = extractJsonLdContacts(html);
  for (const p of jsonLd.phones) addIfNew(p);

  const telMatches = html.match(/tel:([+\d][\d\s().-]{6,18}\d)/gi) || [];
  for (const m of telMatches) addIfNew(m.replace(/^tel:/i, ""));

  const text = getVisibleText(html);
  const pattern = /(?<!\d)(\+?\d{1,3}[\s-]?)?\(?\d{3}\)?[\s-]\d{3}[\s-]\d{4}(?!\d)/g;
  const matches = text.match(pattern) || [];
  for (const m of matches) addIfNew(m);

  return [...seenDigits.values()].slice(0, 10);
}

function extractEmails(html: string): string[] {
  const seen = new Set<string>();
  const ordered: string[] = [];

  function addIfNew(raw: string) {
    const normalized = raw.trim().toLowerCase();
    if (!seen.has(normalized)) {
      seen.add(normalized);
      ordered.push(raw.trim());
    }
  }

  const jsonLd = extractJsonLdContacts(html);
  for (const e of jsonLd.emails) addIfNew(e);

  const text = getVisibleText(html);
  const matches = text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [];
  for (const m of matches) addIfNew(m);

  return ordered.slice(0, 10);
}

/**
 * Heuristically distinguishes a bot/firewall-blocked response (Cloudflare
 * challenge, WAF, rate-limiter, etc.) from a genuinely broken/dead site.
 * Only called when the response was NOT a normal 2xx/3xx — i.e. we already
 * know it isn't straightforwardly "live". This never changes whether a site
 * is fetched or how long we wait for it; it only classifies a response we
 * already have in hand.
 */
function classifyBlocked(status: number, headers: Record<string, string>, text: string): boolean {
  const blockSignatures = [
    "cloudflare", "cf-ray", "cf-mitigated", "attention required", "checking your browser",
    "just a moment", "captcha", "are you a robot", "unusual traffic", "access denied",
    "incapsula", "sucuri", "perimeterx", "datadome", "akamai", "bot detection",
    "request unsuccessful", "verify you are human", "blocked by", "forbidden by policy",
    "security check", "ddos protection", "please enable javascript and cookies"
  ];

  const headerBlob = Object.entries(headers || {})
    .map(([k, v]) => `${k}: ${v}`)
    .join("\n")
    .toLowerCase();
  const bodyBlob = (text || "").slice(0, 4000).toLowerCase();
  const combined = headerBlob + "\n" + bodyBlob;

  if (blockSignatures.some((sig) => combined.includes(sig))) return true;

  // Status codes overwhelmingly used by bot-protection/WAF layers rather
  // than by a normally misconfigured or offline site.
  return status === 403 || status === 429 || status === 503 || status === 999;
}


async function fetchTextWithinBudget(url: string): Promise<{ text: string; status: number; headers: Record<string, string> } | null> {
  const budget = Math.min(remainingMs(), 4000);
  if (budget < 500) return null; // not enough time left to bother trying

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), budget);

  try {
    const res = await fetch(url, {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: {
        // A standard desktop-Chrome UA — many sites (and bot-protection
        // layers) treat an unrecognized/custom UA as an automatic block
        // signal, which previously misclassified live-but-shielded sites
        // as fully dead.
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
      },
    });
    clearTimeout(timeoutId);
    const headers: Record<string, string> = {};
    res.headers.forEach((value, key) => { headers[key] = value; });
    const contentType = headers["content-type"] || "";
    if (!contentType.includes("text")) return { text: "", status: res.status, headers };
    const text = (await res.text()).slice(0, 200000);
    return { text, status: res.status, headers };
  } catch {
    clearTimeout(timeoutId);
    return null;
  }
}

export default async (req: Request, _context: Context): Promise<Response> => {
  if (req.method !== "GET" && req.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405,
      headers: { "content-type": "application/json" },
    });
  }

  let targetUrl: string | null = null;
  if (req.method === "GET") {
    targetUrl = new URL(req.url).searchParams.get("url");
  } else {
    try {
      const body = await req.json();
      targetUrl = body?.url ?? null;
    } catch {
      targetUrl = null;
    }
  }

  if (!targetUrl) {
    return new Response(JSON.stringify({ error: "Missing 'url' parameter" }), {
      status: 400,
      headers: { "content-type": "application/json" },
    });
  }

  const normalized = /^https?:\/\//i.test(targetUrl) ? targetUrl : `https://${targetUrl}`;

  const result: VerifyResult = {
    url: normalized,
    live: false,
    blocked: false,
    statusCode: null,
    phonesFoundOnPage: [],
    emailsFoundOnPage: [],
    checkedSubpage: null,
    error: null,
  };

  const homepage = await fetchTextWithinBudget(normalized);

  if (!homepage) {
    result.error = "Could not reach the site (timed out or connection failed)";
    result.live = false;
    return new Response(JSON.stringify(result), { status: 200, headers: { "content-type": "application/json" } });
  }

  result.statusCode = homepage.status;
  result.live = homepage.status >= 200 && homepage.status < 400;

  if (!result.live) {
    // Distinguish a real, live-but-bot-shielded site (Cloudflare/WAF/rate
    // limiter) from a genuinely dead one — the fetch/timeout mechanics
    // above are unchanged either way, this only classifies the response.
    result.blocked = classifyBlocked(homepage.status, homepage.headers, homepage.text);
  }

  if (result.live && homepage.text) {
    result.phonesFoundOnPage = extractPhones(homepage.text);
    result.emailsFoundOnPage = extractEmails(homepage.text);
  }

  // Homepage had nothing — try a couple of likely sub-pages, stopping as
  // soon as one yields a result, and never exceeding the shared deadline.
  if (result.live && result.phonesFoundOnPage.length === 0 && result.emailsFoundOnPage.length === 0) {
    let origin: string | null = null;
    try {
      origin = new URL(normalized).origin;
    } catch {
      origin = null;
    }

    if (origin) {
      for (const path of ["/contact", "/contact-us", "/about"]) {
        if (remainingMs() < 800) break; // not enough budget left to try another page
        const sub = await fetchTextWithinBudget(origin + path);
        if (!sub || !sub.text || sub.status >= 400) continue;

        const subPhones = extractPhones(sub.text);
        const subEmails = extractEmails(sub.text);
        if (subPhones.length > 0 || subEmails.length > 0) {
          result.phonesFoundOnPage = subPhones;
          result.emailsFoundOnPage = subEmails;
          result.checkedSubpage = origin + path;
          break;
        }
      }
    }
  }

  return new Response(JSON.stringify(result), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
};

export const config: Config = {
  path: "/api/verifyLead",
};
