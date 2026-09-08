/**
 * Regex signatures for known secret/credential formats.
 * Ported from the CLI scanner's pattern library so both tools agree.
 *
 * severity: "critical" | "high" | "medium" | "low"
 */
const SECRET_PATTERNS = [
  // --- Cloud providers ---
  { name: "AWS Access Key ID", severity: "critical",
    regex: /\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/g },
  { name: "AWS Secret Access Key", severity: "critical",
    regex: /aws(.{0,20})?(secret|private)?.{0,3}(key|access).{0,3}[:=]\s*['"]?[A-Za-z0-9/+=]{40}['"]?/gi },
  { name: "GCP Service Account Key", severity: "critical",
    regex: /"type":\s*"service_account"/g },
  { name: "GCP API Key", severity: "high",
    regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g },
  { name: "Azure Storage Account Key", severity: "critical",
    regex: /AccountKey=[A-Za-z0-9+/=]{88}/gi },

  // --- Source control / CI ---
  { name: "GitHub Token", severity: "critical",
    regex: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g },
  { name: "GitHub Fine-Grained PAT", severity: "critical",
    regex: /\bgithub_pat_[A-Za-z0-9_]{22,255}\b/g },
  { name: "GitLab Personal Access Token", severity: "critical",
    regex: /\bglpat-[A-Za-z0-9\-_]{20}\b/g },

  // --- Messaging / collaboration ---
  { name: "Slack Token", severity: "high",
    regex: /\bxox[baprs]-[0-9A-Za-z\-]{10,72}\b/g },
  { name: "Slack Webhook URL", severity: "medium",
    regex: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Za-z]{8,10}\/B[0-9A-Za-z]{8,10}\/[0-9A-Za-z]{24}/g },
  { name: "Discord Bot Token", severity: "high",
    regex: /\b[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b/g },
  { name: "Discord Webhook URL", severity: "medium",
    regex: /https:\/\/discord(app)?\.com\/api\/webhooks\/\d+\/[\w-]+/g },

  // --- Payments ---
  { name: "Stripe API Key", severity: "critical",
    regex: /\b(sk|rk)_(live|test)_[0-9A-Za-z]{24,247}\b/g },
  { name: "Square Access Token", severity: "critical",
    regex: /\bsq0(atp|csp)-[0-9A-Za-z\-_]{22,43}\b/g },
  { name: "PayPal Braintree Access Token", severity: "critical",
    regex: /\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b/g },

  // --- Email / SMS ---
  { name: "SendGrid API Key", severity: "high",
    regex: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g },
  { name: "Twilio API Key", severity: "high",
    regex: /\bSK[0-9a-fA-F]{32}\b/g },
  { name: "Mailgun API Key", severity: "medium",
    regex: /\bkey-[0-9a-zA-Z]{32}\b/g },

  // --- Generic auth structures ---
  { name: "Generic API Key Assignment", severity: "medium",
    regex: /\b(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*['"][A-Za-z0-9_\-.+/=]{16,}['"]/gi },
  { name: "JWT Token", severity: "medium",
    regex: /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g },
  { name: "Private Key Block", severity: "critical",
    regex: /-----BEGIN\s?(RSA|EC|DSA|OPENSSH|PGP)?\s?PRIVATE KEY-----/g },
  { name: "Basic Auth in URL", severity: "medium",
    regex: /\b[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^/\s:@]+:[^/\s:@]+@[^/\s]+/g },
  { name: "Database Connection String", severity: "high",
    regex: /\b(postgres|postgresql|mysql|mongodb(\+srv)?|redis):\/\/[^:\s]+:[^@\s]+@[^\s'"]+/gi },
  { name: "NPM Token", severity: "high",
    regex: /\bnpm_[A-Za-z0-9]{36}\b/g },
];

/**
 * Filenames to always skip regardless of extension — usually huge,
 * auto-generated, and a rich source of high-entropy false positives.
 */
const SKIP_FILENAME_PATTERNS = [
  /(^|\/)package-lock\.json$/,
  /(^|\/)yarn\.lock$/,
  /(^|\/)pnpm-lock\.yaml$/,
  /(^|\/)Pipfile\.lock$/,
  /(^|\/)poetry\.lock$/,
  /(^|\/)Gemfile\.lock$/,
  /(^|\/)composer\.lock$/,
  /(^|\/)cargo\.lock$/i,
  /\.min\.(js|css)$/,
  /\.map$/,
];

/** Directory segments to skip entirely. */
const SKIP_DIRS = new Set([
  "node_modules", "vendor", "dist", "build", ".git", "target",
  "__pycache__", ".venv", "venv", "coverage", ".next", ".nuxt",
  ".gradle", "bin", "obj",
]);

/** Extensions that are binary or otherwise never worth scanning as text. */
const SKIP_EXTENSIONS = new Set([
  "png", "jpg", "jpeg", "gif", "bmp", "ico", "webp", "tiff",
  "mp4", "mov", "avi", "mkv", "webm", "mp3", "wav", "flac", "ogg",
  "zip", "tar", "gz", "tgz", "7z", "rar", "bz2",
  "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
  "ttf", "woff", "woff2", "eot", "otf",
  "exe", "dll", "so", "dylib", "class", "jar", "pyc", "o", "a", "lib",
  "bin", "dat", "db", "sqlite", "sqlite3", "wasm",
]);

if (typeof module !== "undefined") {
  module.exports = { SECRET_PATTERNS, SKIP_FILENAME_PATTERNS, SKIP_DIRS, SKIP_EXTENSIONS };
}
