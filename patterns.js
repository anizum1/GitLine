"use strict";

/**
 * Regex signatures for known secret/credential formats.
 *
 * severity: "critical" | "high" | "medium" | "low"
 *
 * Every regex carries the /g flag; callers are responsible for resetting
 * `lastIndex` before a scan (scanning is synchronous, so a single shared
 * object per pattern is safe).
 */
const SECRET_PATTERNS = [
  // --- Cloud providers ---
  { name: "AWS Access Key ID", severity: "critical",
    regex: /\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/g },
  { name: "AWS Secret Access Key", severity: "critical",
    regex: /aws(.{0,20})?(secret|private)?.{0,3}(key|access).{0,3}[:=]\s*['"]?[A-Za-z0-9/+=]{40}['"]?/gi },
  { name: "AWS Session Token", severity: "high",
    regex: /\baws_session_token\s*[:=]\s*['"]?[A-Za-z0-9/+=]{100,}['"]?/gi },
  { name: "GCP Service Account Key", severity: "critical",
    regex: /"type":\s*"service_account"/g },
  { name: "GCP API Key", severity: "high",
    regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g },
  { name: "Google OAuth Client Secret", severity: "high",
    regex: /\bGOCSPX-[A-Za-z0-9\-_]{28}\b/g },
  { name: "Azure Storage Account Key", severity: "critical",
    regex: /AccountKey=[A-Za-z0-9+/=]{88}/gi },
  { name: "Azure AD Client Secret", severity: "critical",
    regex: /\b[A-Za-z0-9~._-]{3}8Q~[A-Za-z0-9~._-]{34}\b/g },
  { name: "DigitalOcean Personal Access Token", severity: "critical",
    regex: /\bdop_v1_[a-f0-9]{64}\b/g },
  { name: "Heroku API Key", severity: "high",
    regex: /\bheroku[a-z0-9_ .\-,]{0,25}[:=]\s*['"][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}['"]/gi },
  { name: "Cloudflare API Token", severity: "high",
    regex: /\bcloudflare[a-z0-9_ .\-,]{0,25}[:=]\s*['"][A-Za-z0-9_-]{40}['"]/gi },

  // --- Source control / CI / package registries ---
  { name: "GitHub Token", severity: "critical",
    regex: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g },
  { name: "GitHub Fine-Grained PAT", severity: "critical",
    regex: /\bgithub_pat_[A-Za-z0-9_]{22,255}\b/g },
  { name: "GitLab Personal Access Token", severity: "critical",
    regex: /\bglpat-[A-Za-z0-9\-_]{20}\b/g },
  { name: "NPM Token", severity: "high",
    regex: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { name: "npmrc Auth Token", severity: "high",
    regex: /_authToken\s*=\s*[A-Za-z0-9_\-./+=]{16,}/g },
  { name: "PyPI Upload Token", severity: "high",
    regex: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}\b/g },
  { name: "Docker Registry Auth", severity: "high",
    regex: /"auths?"\s*:\s*\{[^}]{0,200}?"auth"\s*:\s*"[A-Za-z0-9+/=]{16,}"/g },
  { name: "Terraform Cloud Token", severity: "high",
    regex: /\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9\-_=]{60,}\b/g },

  // --- AI / model providers ---
  { name: "OpenAI API Key", severity: "critical",
    regex: /\bsk-(proj-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b/g },
  { name: "Anthropic API Key", severity: "critical",
    regex: /\bsk-ant-(api|admin)[0-9]{2}-[A-Za-z0-9\-_]{80,}\b/g },
  { name: "Hugging Face Access Token", severity: "high",
    regex: /\bhf_[A-Za-z0-9]{34}\b/g },

  // --- Messaging / collaboration ---
  { name: "Slack Token", severity: "high",
    regex: /\bxox[baprs]-[0-9A-Za-z\-]{10,72}\b/g },
  { name: "Slack Webhook URL", severity: "medium",
    regex: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Za-z]{8,10}\/B[0-9A-Za-z]{8,10}\/[0-9A-Za-z]{24}/g },
  { name: "Discord Bot Token", severity: "high",
    regex: /\b[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b/g },
  { name: "Discord Webhook URL", severity: "medium",
    regex: /https:\/\/discord(app)?\.com\/api\/webhooks\/\d+\/[\w-]+/g },
  { name: "Telegram Bot Token", severity: "high",
    regex: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/g },
  { name: "Atlassian API Token", severity: "high",
    regex: /\bATATT3[A-Za-z0-9_\-=]{180,}\b/g },

  // --- Payments ---
  { name: "Stripe API Key", severity: "critical",
    regex: /\b(sk|rk)_(live|test)_[0-9A-Za-z]{24,247}\b/g },
  { name: "Square Access Token", severity: "critical",
    regex: /\bsq0(atp|csp)-[0-9A-Za-z\-_]{22,43}\b/g },
  { name: "PayPal Braintree Access Token", severity: "critical",
    regex: /\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b/g },
  { name: "Shopify Access Token", severity: "critical",
    regex: /\bshp(at|ca|pa|ss)_[a-fA-F0-9]{32}\b/g },

  // --- Email / SMS ---
  { name: "SendGrid API Key", severity: "high",
    regex: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g },
  { name: "Twilio API Key", severity: "high",
    regex: /\bSK[0-9a-fA-F]{32}\b/g },
  { name: "Mailgun API Key", severity: "medium",
    regex: /\bkey-[0-9a-zA-Z]{32}\b/g },
  { name: "Postmark Server Token", severity: "medium",
    regex: /\bpostmark[a-z0-9_ .\-,]{0,25}[:=]\s*['"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['"]/gi },

  // --- Data / observability / SaaS ---
  { name: "Supabase Service Role Key", severity: "critical",
    regex: /\bsb_secret_[A-Za-z0-9_-]{20,}\b/g },
  { name: "Datadog API Key", severity: "high",
    regex: /\b(dd|datadog)[a-z0-9_ .\-,]{0,25}(api|app)[_-]?key\s*[:=]\s*['"][a-f0-9]{32}['"]/gi },
  { name: "Sentry DSN with Secret", severity: "medium",
    regex: /https:\/\/[0-9a-f]{32}:[0-9a-f]{32}@[\w.-]*sentry\.io\/\d+/g },
  { name: "Algolia Admin Key", severity: "high",
    regex: /\balgolia[a-z0-9_ .\-,]{0,25}(admin|api)[_-]?key\s*[:=]\s*['"][a-f0-9]{32}['"]/gi },
  { name: "Airtable API Key", severity: "high",
    regex: /\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b/g },
  { name: "Dropbox Access Token", severity: "high",
    regex: /\bsl\.[A-Za-z0-9_-]{130,}\b/g },
  { name: "New Relic License Key", severity: "medium",
    regex: /\bNRAK-[A-Z0-9]{27}\b/g },

  // --- Generic auth structures ---
  { name: "Generic API Key Assignment", severity: "medium",
    regex: /\b(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*['"][A-Za-z0-9_\-.+/=]{16,}['"]/gi },
  { name: "Generic Password Assignment", severity: "low",
    regex: /\b(password|passwd|pwd)\b\s*[:=]\s*['"][^'"\s]{8,}['"]/gi },
  { name: "JWT Token", severity: "medium",
    regex: /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g },
  { name: "Private Key Block", severity: "critical",
    regex: /-----BEGIN\s?(RSA|EC|DSA|OPENSSH|PGP)?\s?PRIVATE KEY-----/g },
  { name: "PuTTY Private Key", severity: "critical",
    regex: /PuTTY-User-Key-File-\d+:/g },
  { name: "Basic Auth in URL", severity: "medium",
    regex: /\b[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^/\s:@]+:[^/\s:@]+@[^/\s]+/g },
  { name: "Database Connection String", severity: "high",
    regex: /\b(postgres|postgresql|mysql|mongodb(\+srv)?|redis|amqp):\/\/[^:\s]+:[^@\s]+@[^\s'"]+/gi },
];

/**
 * Patterns that are meaningful even inside generated/lockfile content.
 * Lockfiles are dense with integrity hashes, so the entropy pass is
 * useless there — but a registry token committed into one is very real.
 */
const LOCKFILE_SAFE_PATTERN_NAMES = new Set([
  "npmrc Auth Token", "NPM Token", "GitHub Token", "GitHub Fine-Grained PAT",
  "Basic Auth in URL", "Database Connection String", "PyPI Upload Token",
  "Docker Registry Auth", "GitLab Personal Access Token",
]);

/** Lockfiles and generated artifacts: skipped by default, scanned in deep mode. */
const LOCKFILE_PATTERNS = [
  /(^|\/)package-lock\.json$/,
  /(^|\/)yarn\.lock$/,
  /(^|\/)pnpm-lock\.yaml$/,
  /(^|\/)Pipfile\.lock$/,
  /(^|\/)poetry\.lock$/,
  /(^|\/)Gemfile\.lock$/,
  /(^|\/)composer\.lock$/,
  /(^|\/)cargo\.lock$/i,
  /(^|\/)go\.sum$/,
  /(^|\/)packages\.lock\.json$/,
  /\.min\.(js|css)$/,
  /\.map$/,
];

/** Back-compat alias — the original name for the lockfile list. */
const SKIP_FILENAME_PATTERNS = LOCKFILE_PATTERNS;

/** Directory segments skipped by default (dependency and build output trees). */
const SKIP_DIRS = new Set([
  "node_modules", "vendor", "dist", "build", ".git", "target",
  "__pycache__", ".venv", "venv", "coverage", ".next", ".nuxt",
  ".gradle", "bin", "obj",
]);

/**
 * Binary extensions. Skipped by default; in deep mode they are downloaded as
 * bytes and run through a `strings`-style extractor instead of being decoded
 * as text. Compressed and media containers stay excluded even in deep mode —
 * their bytes are entropy noise that no extractor can make sense of.
 */
const BINARY_EXTENSIONS = new Set([
  "png", "jpg", "jpeg", "gif", "bmp", "ico", "webp", "tiff",
  "mp4", "mov", "avi", "mkv", "webm", "mp3", "wav", "flac", "ogg",
  "zip", "tar", "gz", "tgz", "7z", "rar", "bz2",
  "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
  "ttf", "woff", "woff2", "eot", "otf",
  "exe", "dll", "so", "dylib", "class", "jar", "pyc", "o", "a", "lib",
  "bin", "dat", "db", "sqlite", "sqlite3", "wasm",
]);

/** Back-compat alias — the original name for the binary extension set. */
const SKIP_EXTENSIONS = BINARY_EXTENSIONS;

/**
 * Binary formats worth running the strings extractor over in deep mode.
 * Compiled objects and embedded databases routinely carry literal keys;
 * a JPEG does not.
 */
const STRINGS_WORTHY_EXTENSIONS = new Set([
  "exe", "dll", "so", "dylib", "class", "jar", "pyc", "o", "a", "lib",
  "bin", "dat", "db", "sqlite", "sqlite3", "wasm", "pdf",
]);

if (typeof module !== "undefined") {
  module.exports = {
    SECRET_PATTERNS, LOCKFILE_PATTERNS, SKIP_FILENAME_PATTERNS,
    LOCKFILE_SAFE_PATTERN_NAMES, SKIP_DIRS, BINARY_EXTENSIONS,
    SKIP_EXTENSIONS, STRINGS_WORTHY_EXTENSIONS,
  };
}
