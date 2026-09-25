/**
 * Secret redaction for what leaves the machine. Applied to every string of the
 * Jev state before it is serialised; the transcript returned to the host is
 * never touched. Only high-confidence shapes are replaced, each with a typed
 * placeholder (`[REDACTED:aws_key]`), so Jev still sees that a key was there
 * and everything around it stays verbatim.
 */

const placeholder = (type: string): string => `[REDACTED:${type}]`;

/** Mixed case or a digit: tells a token from an English word. */
function looksRandom(value: string): boolean {
  return /\d/.test(value) || (/[a-z]/.test(value) && /[A-Z]/.test(value));
}

interface TokenRule {
  pattern: RegExp;
  type: (match: string) => string;
  accept?: (match: string) => boolean;
}

/** Secrets recognisable from their own shape, wherever they appear. */
const TOKEN_RULES: TokenRule[] = [
  {
    // Unterminated blocks (a cut-off paste) lose the base64 run that follows.
    pattern:
      /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----(?:[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----|(?:[A-Za-z0-9+/=\s:,-]|\\[nr])*)/g,
    type: () => 'private_key',
  },
  { pattern: /\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/g, type: () => 'aws_key' },
  {
    pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b/g,
    type: () => 'github_token',
  },
  {
    pattern: /\bsk-[A-Za-z0-9_-]{20,}/g,
    type: (match) =>
      match.startsWith('sk-ant-')
        ? 'anthropic_key'
        : match.startsWith('sk-or-')
          ? 'openrouter_key'
          : 'openai_key',
    accept: (match) => /\d/.test(match),
  },
  { pattern: /\b(?:xox[abposr]-[A-Za-z0-9-]{10,}|xapp-\d-[A-Za-z0-9-]{10,})/g, type: () => 'slack_token' },
  { pattern: /\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])/g, type: () => 'google_api_key' },
  {
    pattern: /\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}/g,
    type: () => 'jwt',
  },
];

/** `scheme://user:password@host`: the user stays, the password goes. */
const URL_PASSWORD = /(?<![a-z0-9+.-])([a-z][a-z0-9+.-]*:\/\/[^\s:/@[\]]+:)([^\s@/]+)@/gi;

/** `Bearer <token>` / `Basic <credentials>`: the scheme stays, the value goes. */
const AUTH_SCHEME = /\b(Bearer|Basic)(\s+)([A-Za-z0-9._~+/-]+=*)/gi;
/** `Authorization: <token>` without a scheme. */
const AUTH_RAW = /\b(authorization["']?\s*[:=]\s*["']?)(?!Bearer\b|Basic\b)([A-Za-z0-9._~+/-]+=*)/gi;

/** The secret word must end the key name, optionally followed by `_key` or digits. */
const SECRET_KEY =
  /(?:password|passwd|passphrase|secret|token|api[_-]?key|private[_-]?key|credentials?|access[_-]?key)(?:[_-]?(?:key|value))?\d*$/i;

/**
 * Whether a key name says its value is a credential: `DB_PASSWORD`, `apiKey`,
 * `client_secret`, `githubToken`, `SECRET_KEY`. Only the last dotted segment
 * counts, and the secret word must end it, so `max_tokens`, `tokenizer`,
 * `Unexpected_token_1012`, `CredentialField` and `token.close` do not match.
 */
export function isSecretKey(key: string): boolean {
  return SECRET_KEY.test(key.slice(key.lastIndexOf('.') + 1));
}

const NOT_A_VALUE = /^(?:true|false|null|none|nil|undefined|yes|no)$/i;
const REFERENCE = /^(?:\$|%|<|\{\{|process\.env|os\.environ|import\.meta\.env|env\.)/;
/** An environment variable name (`DB_PASSWORD`), not its value. */
const ENV_NAME = /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/;
const DOTTED_NAME = /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/;

/**
 * Whether the value of a secret-named key is a literal worth hiding rather
 * than a placeholder, reference or type. Quoted values need four characters
 * and a digit, symbol, mixed case or length 8 (so `"include"` stays); unquoted
 * values need a digit or symbol, or 16 characters, so `token: string` and
 * `token=readToken()` are left alone.
 */
export function isLiteralSecret(value: string, quoted: boolean): boolean {
  const text = value.trim();
  if (text.length === 0 || text.startsWith('[REDACTED')) return false;
  if (NOT_A_VALUE.test(text) || /^\d+$/.test(text) || REFERENCE.test(text)) return false;
  if (/^(.)\1*$/.test(text) || /^[*x•.]+$/i.test(text)) return false;
  if (ENV_NAME.test(text)) return false;
  if (quoted) return text.length >= 4 && (looksRandom(text) || /[^A-Za-z]/.test(text) || text.length >= 8);
  if (DOTTED_NAME.test(text)) return false;
  return /[^A-Za-z_]/.test(text) || text.length >= 16;
}

/**
 * `key: "value"`, `"key": "value"`, `key = 'value'` in any language. The
 * lookbehind starts a key only at a name boundary, keeping long runs linear.
 */
const QUOTED_PAIR = /(?<![\w.-])(["'`]?)([A-Za-z_][\w.-]*)\1(\s*[:=]\s*)(["'`])((?:\\.|(?!\4)[^\\\n])*)\4/g;
/** `KEY=value` in env files, shell commands, CLI flags and query strings. */
const BARE_ASSIGNMENT = /(^|[\s;&|(?])(-{0,2})([A-Za-z_][\w.-]*)=(?![=\s"'`])([^\s"'`;,&|()<>{}[\]]+)/gm;
/** `key: value` alone on a YAML line. */
const YAML_PAIR = /^([ \t]*-?[ \t]*)([A-Za-z_][\w.-]*)(:[ \t]+)(?![\s"'`|>&*!{[])([^\s#;,]+)[ \t]*$/gm;

/**
 * Replaces high-confidence secrets in `text` with typed placeholders:
 * private key blocks, provider API keys and tokens, JWTs, passwords in URLs,
 * Authorization values, and the literal values of secret-named assignments (the key name
 * stays). Ordinary code, ids and hashes are left as they are.
 */
export function redactText(text: string): string {
  let out = text;
  for (const rule of TOKEN_RULES) {
    out = out.replace(rule.pattern, (match) =>
      rule.accept && !rule.accept(match) ? match : placeholder(rule.type(match)),
    );
  }
  out = out.replace(URL_PASSWORD, (match, prefix: string, password: string) =>
    password.startsWith('[REDACTED') ? match : `${prefix}${placeholder('url_password')}@`,
  );
  out = out.replace(AUTH_SCHEME, (match, scheme: string, space: string, value: string) =>
    value.length >= 12 && looksRandom(value) ? `${scheme}${space}${placeholder('bearer')}` : match,
  );
  out = out.replace(AUTH_RAW, (match, prefix: string, value: string) =>
    value.length >= 16 && looksRandom(value) ? `${prefix}${placeholder('bearer')}` : match,
  );
  out = out.replace(
    QUOTED_PAIR,
    (match, keyQuote: string, key: string, separator: string, quote: string, value: string) =>
      isSecretKey(key) && isLiteralSecret(value, true)
        ? `${keyQuote}${key}${keyQuote}${separator}${quote}${placeholder('secret')}${quote}`
        : match,
  );
  out = out.replace(
    BARE_ASSIGNMENT,
    (match, lead: string, dashes: string, key: string, value: string, offset: number, whole: string) =>
      isSecretKey(key) &&
      isLiteralSecret(value, false) &&
      whole.charAt(offset + match.length) !== '('
        ? `${lead}${dashes}${key}=${placeholder('secret')}`
        : match,
  );
  out = out.replace(YAML_PAIR, (match, lead: string, key: string, separator: string, value: string) =>
    isSecretKey(key) && isLiteralSecret(value, false)
      ? `${lead}${key}${separator}${placeholder('secret')}`
      : match,
  );
  return out;
}

function redactValue(value: unknown, key: string | undefined, seen: WeakSet<object>): unknown {
  if (typeof value === 'string') {
    return key !== undefined && isSecretKey(key) && isLiteralSecret(value, true)
      ? placeholder('secret')
      : redactText(value);
  }
  if (value === null || typeof value !== 'object') return value;
  if (seen.has(value)) return '[circular]';
  seen.add(value);
  if (Array.isArray(value)) return value.map((item) => redactValue(item, undefined, seen));
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) return value;
  return Object.fromEntries(
    Object.entries(value).map(([name, item]) => [name, redactValue(item, name, seen)]),
  );
}

/**
 * A redacted copy of a tool input: every string leaf goes through
 * `redactText`, and string fields with a secret-looking name lose their value.
 * The input itself is not modified.
 */
export function redactInput(input: Record<string, unknown>): Record<string, unknown> {
  return redactValue(input, undefined, new WeakSet()) as Record<string, unknown>;
}
