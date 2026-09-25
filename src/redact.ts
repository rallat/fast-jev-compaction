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
    // A block with its END line. Stopping at the next BEGIN keeps many
    // unterminated headers in one text linear.
    pattern:
      /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----(?:(?!-----BEGIN )[\s\S])*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----/g,
    type: () => 'private_key',
  },
  {
    // A cut-off block loses only the base64 lines after its header, so prose
    // that merely mentions a header stays.
    pattern:
      /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----(?:(?:\s|\\[nr])*[A-Za-z0-9+/]{16,}={0,2}(?:(?:\s|\\[nr])+[A-Za-z0-9+/]{16,}={0,2})*)?/g,
    type: () => 'private_key',
  },
  { pattern: /\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/g, type: () => 'aws_key' },
  {
    pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b/g,
    type: () => 'github_token',
  },
  {
    pattern: /(?<![\w-])sk-[A-Za-z0-9_-]{20,}/g,
    type: (match) =>
      match.startsWith('sk-ant-')
        ? 'anthropic_key'
        : match.startsWith('sk-or-')
          ? 'openrouter_key'
          : 'openai_key',
    // A digit and one long random run: `sk-loading-spinner-2024` is a CSS class.
    accept: (match) => /\d/.test(match) && /[A-Za-z0-9]{16,}/.test(match),
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

/**
 * An Authorization value after its header name, in a header line, an object
 * or a `setHeader('Authorization', ...)` call. Any scheme word (`Bearer`,
 * `Basic`, `Token`) stays and only the value goes.
 */
const AUTH_HEADER =
  /\b((?:proxy-)?authorization(?:["'`]?\s*[:=]|["'`]\s*,)\s*["'`]?)(?:([A-Za-z][A-Za-z-]*)(\s+))?([A-Za-z0-9._~+/-]+=*)/gi;
/**
 * `Bearer <token>` with no header name. Case-sensitive, and the token needs a
 * digit and no `/`, so prose such as `Bearer AuthenticationProvider` stays.
 */
const BARE_BEARER = /\bBearer(\s+)([A-Za-z0-9._~+-]+=*)(?![\w/])/g;
/** `curl -H "X-Api-Key: <value>"`: a secret-named header in a quoted argument. */
const CURL_HEADER = /((?:^|\s)(?:-H|--header)(?:\s+|=)(["']))([A-Za-z][\w-]*)(:[ \t]*)([^"'\n]+)(?=\2)/g;

/** Whether an Authorization value is a credential rather than a word. */
function isAuthValue(value: string, hasScheme: boolean): boolean {
  return value.length >= (hasScheme ? 12 : 16) && looksRandom(value);
}

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
/** A call or call chain (`getKey()`, `z.string().min(10)`), not a literal. */
const CALL = /^[A-Za-z_$][\w$.]*\(/;
/** Type names a typed field or schema puts where a value would go. */
const TYPE_NAME = /^(?:string|str|number|int|integer|float|boolean|bool|bytes|object|any|unknown|text|char|varchar)$/i;
/** Keys whose value is a password, where even a short word is the secret. */
const PASSWORD_KEY = /(?:password|passwd|passphrase)(?:[_-]?value)?\d*$/i;

/**
 * Whether the value of a secret-named key is a literal worth hiding rather
 * than a placeholder, reference, call or type. Quoted values need four
 * characters and a digit, symbol, mixed case or length 8 (so `"include"`
 * stays); unquoted values need a digit or symbol, or 16 characters, so
 * `token: string` and `token=readToken()` are left alone. When `key` names a
 * password, a lowercase word of four or more letters also counts
 * (`password: letmein`), but not a camelCase variable (`userPassword`).
 */
export function isLiteralSecret(value: string, quoted: boolean, key = ''): boolean {
  const text = value.trim();
  if (text.length === 0 || text.startsWith('[REDACTED')) return false;
  if (NOT_A_VALUE.test(text) || /^\d+$/.test(text) || REFERENCE.test(text)) return false;
  if (/^(.)\1*$/.test(text) || /^[*x•.]+$/i.test(text)) return false;
  if (ENV_NAME.test(text) || TYPE_NAME.test(text)) return false;
  const password = PASSWORD_KEY.test(key.slice(key.lastIndexOf('.') + 1));
  if (quoted) {
    return text.length >= 4 && (password || looksRandom(text) || /[^A-Za-z]/.test(text) || text.length >= 8);
  }
  if (DOTTED_NAME.test(text) || CALL.test(text)) return false;
  return /[^A-Za-z_]/.test(text) || text.length >= 16 || (password && /^[a-z]{4,}$/.test(text));
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
  out = out.replace(AUTH_HEADER, (match, prefix: string, scheme = '', space = '', value: string) =>
    isAuthValue(value, scheme !== '') ? `${prefix}${scheme}${space}${placeholder('bearer')}` : match,
  );
  out = out.replace(BARE_BEARER, (match, space: string, value: string) =>
    value.length >= 16 && /\d/.test(value) && /[A-Za-z]/.test(value) ? `Bearer${space}${placeholder('bearer')}` : match,
  );
  out = out.replace(CURL_HEADER, (match, lead: string, _quote: string, name: string, separator: string, value: string) =>
    isSecretKey(name) && isLiteralSecret(value, true, name) ? `${lead}${name}${separator}${placeholder('secret')}` : match,
  );
  out = out.replace(
    QUOTED_PAIR,
    (match, keyQuote: string, key: string, separator: string, quote: string, value: string) =>
      isSecretKey(key) && isLiteralSecret(value, true, key)
        ? `${keyQuote}${key}${keyQuote}${separator}${quote}${placeholder('secret')}${quote}`
        : match,
  );
  out = out.replace(
    BARE_ASSIGNMENT,
    (match, lead: string, dashes: string, key: string, value: string, offset: number, whole: string) =>
      isSecretKey(key) &&
      isLiteralSecret(value, false, key) &&
      whole.charAt(offset + match.length) !== '('
        ? `${lead}${dashes}${key}=${placeholder('secret')}`
        : match,
  );
  out = out.replace(YAML_PAIR, (match, lead: string, key: string, separator: string, value: string) =>
    isSecretKey(key) && isLiteralSecret(value, false, key)
      ? `${lead}${key}${separator}${placeholder('secret')}`
      : match,
  );
  return out;
}

/** An object field that holds an Authorization header value. */
const AUTH_KEY = /^(?:proxy-)?authorization$/i;

/** `Token abc123...` or a bare token under an Authorization field. */
function redactAuthField(value: string): string {
  const out = redactText(value);
  if (out !== value) return out;
  const parts = /^(\s*)(?:([A-Za-z][A-Za-z-]*)(\s+))?([A-Za-z0-9._~+/-]+=*)(\s*)$/.exec(value);
  if (!parts) return out;
  const [, lead = '', scheme = '', space = '', token = '', trail = ''] = parts;
  return isAuthValue(token, scheme !== '') ? `${lead}${scheme}${space}${placeholder('bearer')}${trail}` : out;
}

/** `ancestors` holds only the objects on the current path, so a shared object is not a cycle. */
function redactValue(value: unknown, key: string | undefined, ancestors: WeakSet<object>): unknown {
  if (typeof value === 'string') {
    if (key !== undefined && AUTH_KEY.test(key)) return redactAuthField(value);
    return key !== undefined && isSecretKey(key) && isLiteralSecret(value, true, key)
      ? placeholder('secret')
      : redactText(value);
  }
  if (value === null || typeof value !== 'object') return value;
  if (ancestors.has(value)) return '[circular]';
  const proto = Object.getPrototypeOf(value);
  if (!Array.isArray(value) && proto !== Object.prototype && proto !== null) return value;
  ancestors.add(value);
  const out = Array.isArray(value)
    ? value.map((item) => redactValue(item, undefined, ancestors))
    : Object.fromEntries(Object.entries(value).map(([name, item]) => [name, redactValue(item, name, ancestors)]));
  ancestors.delete(value);
  return out;
}

/**
 * A redacted copy of a tool input: every string leaf goes through
 * `redactText`, and string fields with a secret-looking name lose their value.
 * The input itself is not modified.
 */
export function redactInput(input: Record<string, unknown>): Record<string, unknown> {
  return redactValue(input, undefined, new WeakSet()) as Record<string, unknown>;
}
