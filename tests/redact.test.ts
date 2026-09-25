import { describe, expect, it } from 'vitest';
import {
  collectToolCalls,
  compact,
  estimateTokens,
  fitState,
  redactInput,
  redactText,
  resolveOptions,
  type JevAsker,
  type Message,
} from '../src/index.js';

/**
 * Secret-shaped fixtures are assembled at runtime so no token-like literal
 * sits in the repository (and trips secret scanners on push).
 */
const join = (...parts: string[]): string => parts.join('');
const alnum = (length: number, seed = 'aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vW0xY'): string =>
  seed.repeat(Math.ceil(length / seed.length)).slice(0, length);

const PEM = join(
  '-----BEGIN ',
  'RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA',
  alnum(64),
  '\n',
  alnum(64),
  '\n-----END ',
  'RSA PRIVATE KEY-----',
);
const OPENSSH = join(
  '-----BEGIN ',
  'OPENSSH PRIVATE KEY-----\n',
  alnum(70),
  '\n-----END ',
  'OPENSSH PRIVATE KEY-----',
);
const AWS = join('AK', 'IA', 'IOSFODNN7EXAMPLE');
const GHP = join('gh', 'p_', alnum(36));
const GHO = join('gh', 'o_', alnum(36));
const GHS = join('gh', 's_', alnum(36));
const GH_PAT = join('github', '_pat_', alnum(22), '_', alnum(59));
const OPENAI = join('s', 'k-', 'proj-', alnum(48));
const ANTHROPIC = join('s', 'k-', 'ant-api03-', alnum(80), '-', alnum(10));
const OPENROUTER = join('s', 'k-', 'or-v1-', 'a1b2c3d4'.repeat(8));
const SLACK = join('xo', 'xb-', '1234567890-', '0987654321-', alnum(24));
const GOOGLE = join('AI', 'za', 'Sy', alnum(33));
const JWT = join(
  'ey',
  'JhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
  '.',
  'ey',
  'JzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ',
  '.',
  'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
);

describe('redactText: high-confidence secrets', () => {
  const cases: Array<[string, string, string]> = [
    ['PEM RSA private key block', `key:\n${PEM}\nafter`, 'private_key'],
    ['PEM OpenSSH private key block', OPENSSH, 'private_key'],
    ['AWS access key id', `aws configure set aws_access_key_id ${AWS}`, 'aws_key'],
    ['GitHub classic token (ghp_)', `git clone https://${GHP}@github.com/o/r`, 'github_token'],
    ['GitHub OAuth token (gho_)', `token is ${GHO}.`, 'github_token'],
    ['GitHub app token (ghs_)', `(${GHS})`, 'github_token'],
    ['GitHub fine-grained token', `use ${GH_PAT} here`, 'github_token'],
    ['OpenAI key', `OPENAI key ${OPENAI}`, 'openai_key'],
    ['Anthropic key', `curl -H "x-api-key: ${ANTHROPIC}"`, 'anthropic_key'],
    ['OpenRouter key', `or: ${OPENROUTER}`, 'openrouter_key'],
    ['Slack token', `slack ${SLACK}`, 'slack_token'],
    ['Google API key', `?key=${GOOGLE}&q=1`, 'google_api_key'],
    ['JWT', `cookie session=${JWT};`, 'jwt'],
  ];

  it.each(cases)('%s', (_name, input, type) => {
    const out = redactText(input);
    expect(out).toContain(`[REDACTED:${type}]`);
    for (const secret of [PEM, OPENSSH, AWS, GHP, GHO, GHS, GH_PAT, OPENAI, ANTHROPIC, OPENROUTER, SLACK, GOOGLE, JWT]) {
      expect(out).not.toContain(secret);
    }
  });

  it('keeps the text around a secret intact', () => {
    expect(redactText(`before ${AWS} after`)).toBe('before [REDACTED:aws_key] after');
    expect(redactText(`key:\n${PEM}\nafter`)).toBe('key:\n[REDACTED:private_key]\nafter');
  });
});

describe('redactText: authorization headers', () => {
  const token = join('abc123', alnum(24));
  const cases: Array<[string, string, string]> = [
    ['Bearer header', `-H "Authorization: Bearer ${token}"`, '-H "Authorization: Bearer [REDACTED:bearer]"'],
    ['lowercase bearer', `authorization: bearer ${token}`, 'authorization: bearer [REDACTED:bearer]'],
    ['Basic header', 'Authorization: Basic dXNlcjpwYXNzd29yZA==', 'Authorization: Basic [REDACTED:bearer]'],
    ['raw Authorization value', `Authorization: ${token}`, 'Authorization: [REDACTED:bearer]'],
  ];
  it.each(cases)('%s', (_name, input, expected) => {
    expect(redactText(input)).toBe(expected);
  });
});

describe('redactText: other authorization schemes and secret-named headers', () => {
  const hex = join('9944b09199c62bcf', '9418ad846dd0e4bbdfc6ee4b');
  const cases: Array<[string, string, string]> = [
    ['Token scheme in a curl header', `curl -H "Authorization: Token ${hex}" x`, 'curl -H "Authorization: Token [REDACTED:bearer]" x'],
    ['setHeader call', `req.setHeader('Authorization', 'token ${hex}')`, "req.setHeader('Authorization', 'token [REDACTED:bearer]')"],
    ['Proxy-Authorization', `Proxy-Authorization: Basic ${hex}`, 'Proxy-Authorization: Basic [REDACTED:bearer]'],
    ['X-Api-Key curl header', `curl -H "X-Api-Key: ${hex}" x`, 'curl -H "X-Api-Key: [REDACTED:secret]" x'],
    ['x-auth-token --header', `curl --header 'x-auth-token: ${hex}' x`, "curl --header 'x-auth-token: [REDACTED:secret]' x"],
    ['bare Bearer token', `use Bearer ${hex} for it`, 'use Bearer [REDACTED:bearer] for it'],
  ];
  it.each(cases)('%s', (_name, input, expected) => {
    expect(redactText(input)).toBe(expected);
  });
});

describe('redactText: passwords in URLs', () => {
  it.each([
    ['postgres://admin:s3cret@db:5432/app', 'postgres://admin:[REDACTED:url_password]@db:5432/app'],
    [`https://x:${GHP}@github.com/o/r`, 'https://x:[REDACTED:github_token]@github.com/o/r'],
    ['see https://example.com:8080/path and git@github.com:o/r.git', 'see https://example.com:8080/path and git@github.com:o/r.git'],
  ])('%s', (input, expected) => {
    expect(redactText(input)).toBe(expected);
  });
});

describe('redactText: secret-named assignments keep the key, drop the value', () => {
  const cases: Array<[string, string, string]> = [
    ['env file', 'DB_PASSWORD=hunter2', 'DB_PASSWORD=[REDACTED:secret]'],
    ['exported env', 'export GITHUB_TOKEN=abc123def456', 'export GITHUB_TOKEN=[REDACTED:secret]'],
    ['inline shell env', 'API_KEY=zz9plural npm run deploy', 'API_KEY=[REDACTED:secret] npm run deploy'],
    ['CLI flag', 'psql --password=s3cr3t!', 'psql --password=[REDACTED:secret]'],
    ['JSON pair', '{"client_secret": "shh-its-a-secret"}', '{"client_secret": "[REDACTED:secret]"}'],
    ['JS object', "const cfg = { apiKey: 'k-12345' };", "const cfg = { apiKey: '[REDACTED:secret]' };"],
    ['python assignment', 'password = "correct horse"', 'password = "[REDACTED:secret]"'],
    ['YAML value', 'db:\n  password: hunter2\n', 'db:\n  password: [REDACTED:secret]\n'],
    ['private_key field', '"private_key": "abc\\ndef"', '"private_key": "[REDACTED:secret]"'],
    ['credential field', 'credential="xyz-789"', 'credential="[REDACTED:secret]"'],
    ['apikey field', 'apikey: "k9k9k9k9"', 'apikey: "[REDACTED:secret]"'],
    ['SECRET_KEY setting', "SECRET_KEY = 'django-insecure-abc'", "SECRET_KEY = '[REDACTED:secret]'"],
    ['dotted config key', 'spring.datasource.password=Pa55word', 'spring.datasource.password=[REDACTED:secret]'],
    ['short quoted password word', 'password = "letmein"', 'password = "[REDACTED:secret]"'],
    ['short env password word', 'DB_PASSWORD=letmein', 'DB_PASSWORD=[REDACTED:secret]'],
    ['short YAML password word', 'password: letmein', 'password: [REDACTED:secret]'],
    ['passphrase word', "passphrase: 'hunter'", "passphrase: '[REDACTED:secret]'"],
  ];
  it.each(cases)('%s', (_name, input, expected) => {
    expect(redactText(input)).toBe(expected);
  });
});

describe('redactText: ordinary code and ids stay untouched', () => {
  const cases: Array<[string, string]> = [
    ['token as a variable', 'const token = await getToken(req);'],
    ['token assignment from a call', 'token=readToken()'],
    ['token assignment from a variable', 'token = accessToken'],
    ['typed field', 'interface Auth {\n  token: string;\n  password: string\n}'],
    ['token counts', 'max_tokens=4096 maxStateTokens: 25000'],
    ['tokenizer', 'tokenizer = "cl100k_base"'],
    ['env reference', 'GITHUB_TOKEN=$GITHUB_TOKEN\npassword: ${DB_PASSWORD}\napiKey: process.env.API_KEY'],
    ['placeholder', 'password="<your password>" token: "***" secret=xxxxxxxx'],
    ['booleans and null', '"secret": null, "token": true, password=false'],
    ['git SHA', 'commit e3f262a4b1c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5 and e3f262a'],
    ['UUID', 'id 123e4567-e89b-12d3-a456-426614174000'],
    ['prose about tokens', 'The bearer token is refreshed; the secret is in the vault. Use a password manager.'],
    ['sk- words without digits', 'uses sk-learn-compatible-estimator and task-abc'],
    ['short Bearer word', 'Bearer auth'],
    ['base64 image data', 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA'],
    ['secret word inside a longer key', '"Unexpected_token_1012": "Unexpected token.", token_count=12abc'],
    ['property of a token object', 'token.close = `)`; token.output = "a+b";'],
    ['type alias with a credential word', 'type RequestCredentials = "include" | "omit";\ntype CredentialField = "webauthn";'],
    ['env var name as the value', 'the credential: `DB_PASSWORD` and token="GITHUB_TOKEN"'],
    ['public key block', '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----'],
    ['sk- inside a CSS class', 'class="sk-loading-spinner-2024-variant"'],
    ['sk- after a hyphen', 'task-sk-12345678901234567890abc'],
    ['Basic before a word with digits', 'the Basic configuration1234567 was fine'],
    ['basic before a file path', 'Add a basic src/components/Header.tsx file with a nav bar'],
    ['Basic before a component name', 'Create a Basic AuthenticationProvider component'],
    ['Bearer before a component name', 'Bearer AuthenticationProvider'],
    ['YAML value that is a call chain', 'accessToken: z.string().min(10)'],
    ['YAML value that is a call', 'password: hashPassword(input)'],
    ['indented YAML call', '  apiKey: getKey()'],
    ['password typed as a type name', 'password: string\npassword = "string"'],
    ['password from a camelCase variable', 'password: userPassword'],
    ['Authorization header name in prose', 'the Authorization header is required'],
    ['authorization followed by a comma in prose', 'for authorization, see AuthController2.ts'],
  ];
  it.each(cases)('%s', (_name, input) => {
    expect(redactText(input)).toBe(input);
  });
});

describe('redactText: cost on long unbroken runs', () => {
  it.each([
    ['letters', 'a'.repeat(100_000)],
    ['dotted names', 'a.'.repeat(50_000)],
    ['dashed names', 'ab-'.repeat(33_000)],
    ['unterminated quotes', 'k: "'.repeat(25_000)],
  ])('stays linear on 100k chars of %s', (_name, input) => {
    const started = Date.now();
    redactText(input);
    expect(Date.now() - started).toBeLessThan(1000);
  });

  it('stays linear on 1 MB of unterminated private key headers', () => {
    const header = join('-----BEGIN ', 'PRIVATE KEY-----.');
    const started = Date.now();
    redactText(header.repeat(Math.ceil(1_000_000 / header.length)));
    expect(Date.now() - started).toBeLessThan(1000);
  });
});

describe('redactText: unterminated private key blocks', () => {
  const header = join('-----BEGIN ', 'PRIVATE KEY-----');
  it('drops the header and the base64 lines after it', () => {
    expect(redactText(`${header}\n${alnum(64)}\n${alnum(64)}\nnext`)).toBe('[REDACTED:private_key]\nnext');
    expect(redactText(`"${header}\\n${alnum(64)}\\n${alnum(40)}"`)).toBe('"[REDACTED:private_key]"');
  });
  it('keeps the prose after a header that is only mentioned', () => {
    expect(
      redactText(`The PEM starts with ${header} and then comes base64, we strip headers\nthen decode it\nnext steps: run tests`),
    ).toBe('The PEM starts with [REDACTED:private_key] and then comes base64, we strip headers\nthen decode it\nnext steps: run tests');
  });
});

describe('redactInput', () => {
  it('redacts string leaves and secret-named fields at any depth without mutating the input', () => {
    const input = {
      command: `export GITHUB_TOKEN=${GHP} && gh pr list`,
      env: { API_KEY: 'plainvalue', PATH: '/usr/bin' },
      headers: [{ Authorization: `Bearer ${join('abc123', alnum(24))}` }],
      count: 3,
      tokenLimit: 5,
    };
    const snapshot = JSON.stringify(input);
    const out = redactInput(input);
    expect(JSON.stringify(input)).toBe(snapshot);
    expect(out).toEqual({
      command: 'export GITHUB_TOKEN=[REDACTED:github_token] && gh pr list',
      env: { API_KEY: '[REDACTED:secret]', PATH: '/usr/bin' },
      headers: [{ Authorization: 'Bearer [REDACTED:bearer]' }],
      count: 3,
      tokenLimit: 5,
    });
  });

  it('redacts Authorization and password fields whatever the value shape', () => {
    const hex = join('9944b09199c62bcf', '9418ad846dd0e4bbdfc6ee4b');
    expect(
      redactInput({
        headers: { Authorization: hex, 'proxy-authorization': `Token ${hex}`, authorization: 'Bearer auth' },
        password: 'hunter',
      }),
    ).toEqual({
      headers: {
        Authorization: '[REDACTED:bearer]',
        'proxy-authorization': 'Token [REDACTED:bearer]',
        authorization: 'Bearer auth',
      },
      password: '[REDACTED:secret]',
    });
  });

  it('only turns true cycles into [circular], not an object shared twice', () => {
    const shared = { a: 1 };
    expect(redactInput({ first: shared, second: shared })).toEqual({ first: { a: 1 }, second: { a: 1 } });
    const cyclic: Record<string, unknown> = { a: 1 };
    cyclic.self = cyclic;
    expect(redactInput(cyclic)).toEqual({ a: 1, self: '[circular]' });
  });
});

function message(role: Message['role'], text: string, extra: Partial<Message> = {}): Message {
  return { role, text, toolUses: [], ...extra };
}

function secretTranscript(): Message[] {
  const env = `DB_PASSWORD=hunter2\nOPENAI_API_KEY=${OPENAI}\n`;
  return [
    message('user', `Deploy with key ${AWS}. Keep src/generated untouched.`),
    message('assistant', '', {
      toolUses: [
        {
          tool_use_id: 'toolu_1',
          tool: 'Bash',
          input: { command: `curl -H "Authorization: Bearer ${GHP}" https://api.github.com` },
          text: 'ok',
        },
      ],
    }),
    message('user', '', { toolResults: [{ tool_use_id: 'toolu_1', text: 'x'.repeat(2000) }] }),
    message('assistant', '', {
      toolUses: [{ tool_use_id: 'toolu_2', tool: 'Read', input: { file_path: '.env' }, text: env }],
    }),
    message('user', '', { toolResults: [{ tool_use_id: 'toolu_2', text: env }] }),
    message('assistant', `The .env holds DB_PASSWORD=hunter2 and ${OPENAI}; I will not print them again.`),
    message('user', `Also here is the deploy key:\n${PEM}\nand the JWT ${JWT}`),
  ];
}

const PLANTED = [AWS, GHP, OPENAI, PEM, JWT, 'hunter2'];

describe('state sent to Jev', () => {
  it('holds no planted secret while the returned transcript keeps every one verbatim', async () => {
    const seen: string[] = [];
    const asker: JevAsker = {
      async ask(state, questions) {
        seen.push(JSON.stringify(state));
        return {
          answers: Object.fromEntries(Object.keys(questions).map((key) => [key, { noul: 1 }])),
        };
      },
    };
    const messages = secretTranscript();
    const before = JSON.stringify(messages);
    const result = await compact(messages, asker, { preserveRecentMessages: 1 });

    expect(seen.length).toBeGreaterThan(0);
    for (const body of seen) {
      for (const secret of [AWS, GHP, OPENAI, JWT, 'hunter2']) expect(body).not.toContain(secret);
      expect(body).not.toContain('PRIVATE KEY');
      expect(body).toContain('DB_PASSWORD=[REDACTED:secret]');
      expect(body).toContain('[REDACTED:aws_key]');
      expect(body).toContain('[REDACTED:private_key]');
      expect(body).toContain('Keep src/generated untouched.');
    }
    expect(JSON.stringify(messages)).toBe(before);
    const returned = JSON.stringify(result.messages);
    for (const secret of [AWS, GHP, OPENAI, JWT]) expect(returned).toContain(JSON.stringify(secret).slice(1, -1));
    expect(result.messages[result.messages.length - 1]!.text).toContain(PEM);
    expect(result.messages[0]).toBe(messages[0]);
  });

  it('redacts a caller-supplied goal too', () => {
    const calls: never[] = [];
    const { state } = fitState(secretTranscript(), calls, {
      maxStateTokens: 25_000,
      preserveRecentMessages: 1,
      goal: `ship it with ${GHP}`,
    });
    expect(state.goal).toBe('ship it with [REDACTED:github_token]');
  });

  it('sends everything verbatim when redactSecrets is false', () => {
    const messages = secretTranscript();
    const { state } = fitState(messages, collectToolCalls(messages, 1), {
      maxStateTokens: 25_000,
      preserveRecentMessages: 1,
      goal: '',
      redactSecrets: false,
    });
    const body = JSON.stringify(state);
    for (const secret of PLANTED) expect(body).toContain(JSON.stringify(secret).slice(1, -1));
  });

  it('defaults redactSecrets to true and honours false', () => {
    expect(resolveOptions().redactSecrets).toBe(true);
    expect(resolveOptions({ redactSecrets: false }).redactSecrets).toBe(false);
  });

  it('barely changes the token estimate: placeholders cost about as much as the secrets', () => {
    for (const secret of [PEM, OPENSSH, GHP, GH_PAT, OPENAI, ANTHROPIC, OPENROUTER, SLACK, GOOGLE, JWT]) {
      expect(estimateTokens(redactText(secret))).toBeLessThanOrEqual(estimateTokens(secret));
    }
    // An AWS key id is short: its placeholder may cost a few tokens more.
    expect(estimateTokens(redactText(AWS)) - estimateTokens(AWS)).toBeLessThanOrEqual(5);

    const options = { maxStateTokens: 25_000, preserveRecentMessages: 1, goal: '' };
    const messages = secretTranscript();
    const calls = collectToolCalls(messages, 1);
    const plain = fitState(messages, calls, { ...options, redactSecrets: false });
    const redacted = fitState(messages, calls, options);
    expect(redacted.tokens).toBeLessThanOrEqual(plain.tokens);
  });
});
