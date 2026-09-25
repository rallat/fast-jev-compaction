/**
 * Live evaluation: runs the real `compact()` over the scripted sessions in
 * `examples/fixtures/` against Jev and reports, per run, the estimated tokens
 * left, which planted facts survived (exact string presence), the decisions,
 * and what Jev billed, next to a rule baseline that truncates every unpinned
 * tool output to its first 300 characters without asking Jev.
 *
 *   OPENROUTER_API_KEY=... npx tsx examples/live-eval.ts [--runs 3]
 *     [--fixture add-baseurl] [--model jev-latest] [--set keepThreshold=0.4]
 *     [--pad 30] [--json out.json] [--dry]
 *
 * `--pad N` inserts N generic filler tool calls (status checks, listings,
 * searches, file reads unrelated to the planted facts) into the older part of
 * each session, so the keep budget is contested by many small outputs, as in
 * a long real session. Each run also prints the character reduction and flags
 * runs below the hook's `minReductionRatio` (0.25), where the hook would fall
 * back to the built-in summary after paying for Jev.
 *
 * With `OPENROUTER_API_KEY` it calls OpenRouter's System One endpoint, else
 * TypeSafe's with `TYPESAFE_API_KEY`. `--dry` makes no request and only
 * reports the state size and the rule baseline. Every live run costs real Jev
 * requests, so this is not part of `npm test`.
 */
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  applyDecisions,
  collectToolCalls,
  compact,
  estimateTokens,
  fitState,
  JevClient,
  reductionRatio,
  resolveOptions,
  type CallDecision,
  type CompactOptions,
  type CompactResult,
  type JevAsker,
  type JevQuestions,
  type JevState,
  type Message,
} from '../src/index.js';

const OPENROUTER_URL = 'https://openrouter.ai/api/v1/systemone';
const RULE_HEAD_CHARS = 300;
/** The hook's default `minReductionRatio`; below it the hook falls back. */
const MIN_REDUCTION_RATIO = 0.25;

interface Fact {
  name: string;
  needle: string;
}

interface Fixture {
  name: string;
  description: string;
  preserveRecentMessages: number;
  facts: Fact[];
  messages: Message[];
}

interface Usage {
  ms: number;
  model?: string;
  inputTokens?: number;
  outputTokens?: number;
  cost?: number;
}

interface Args {
  runs: number;
  fixtures: string[];
  model: string;
  set: CompactOptions;
  json?: string;
  dry: boolean;
  pad: number;
}

function parseValue(raw: string): unknown {
  if (raw === 'true' || raw === 'false') return raw === 'true';
  const n = Number(raw);
  return raw.trim() !== '' && Number.isFinite(n) ? n : raw;
}

function parseArgs(argv: readonly string[]): Args {
  const args: Args = {
    runs: 1,
    fixtures: [],
    model: process.env.JEV_MODEL ?? 'jev-latest',
    set: {},
    dry: false,
    pad: 0,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const flag = argv[i];
    const value = (): string => {
      const next = argv[(i += 1)];
      if (next === undefined) throw new Error(`${flag} needs a value`);
      return next;
    };
    if (flag === '--runs') args.runs = Math.max(1, Number(value()));
    else if (flag === '--fixture') args.fixtures.push(value());
    else if (flag === '--model') args.model = value();
    else if (flag === '--json') args.json = value();
    else if (flag === '--dry') args.dry = true;
    else if (flag === '--pad') args.pad = Math.max(0, Math.floor(Number(value())));
    else if (flag === '--set') {
      const [key, raw] = value().split('=', 2);
      if (!key || raw === undefined) throw new Error('--set expects key=value');
      (args.set as Record<string, unknown>)[key] = parseValue(raw);
    } else throw new Error(`unknown argument ${flag}`);
  }
  return args;
}

function loadFixtures(names: readonly string[]): Fixture[] {
  const dir = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');
  const all = readdirSync(dir)
    .filter((file) => file.endsWith('.json'))
    .sort()
    .map((file) => JSON.parse(readFileSync(join(dir, file), 'utf8')) as Fixture);
  const picked = names.length === 0 ? all : all.filter((f) => names.includes(f.name));
  if (picked.length === 0) throw new Error(`no fixture named ${names.join(', ')}`);
  return picked;
}

/** Generic filler outputs of varied size, unrelated to any fixture's facts. */
function fillerCall(i: number): { tool: string; input: Record<string, unknown>; text: string } {
  const n = i + 1;
  switch (i % 5) {
    case 0:
      return {
        tool: 'Bash',
        input: { command: 'git status --short' },
        text: Array.from({ length: 8 }, (_, k) => ` M docs/notes-${n}-${k}.md`).join('\n'),
      };
    case 1:
      return {
        tool: 'Bash',
        input: { command: `ls -la assets/batch-${n}` },
        text: Array.from(
          { length: 12 },
          (_, k) => `-rw-r--r--  1 dev  staff  ${1024 + k * 37} Sep 20 10:${10 + k} image-${n}-${k}.png`,
        ).join('\n'),
      };
    case 2:
      return {
        tool: 'Grep',
        input: { pattern: `legacyOption${n}`, path: 'docs' },
        text: Array.from(
          { length: 6 },
          (_, k) => `docs/archive/guide-${k}.md:${12 + k}: the legacyOption${n} flag was retired in an earlier release`,
        ).join('\n'),
      };
    case 3:
      return {
        tool: 'Read',
        input: { file_path: `docs/archive/changelog-${n}.md` },
        text: Array.from(
          { length: 40 },
          (_, k) => `- Entry ${n}.${k}: tidied wording in the contributor guide and refreshed screenshots`,
        ).join('\n'),
      };
    default:
      return { tool: 'Bash', input: { command: `du -sh assets/batch-${n}` }, text: `${4 + n}.2M\tassets/batch-${n}` };
  }
}

/**
 * Inserts `count` filler call/result pairs at message boundaries in the older
 * part of the session (never between a call and its result, never into the
 * first or the preserved newest messages).
 */
function padSession(messages: readonly Message[], count: number, preserve: number): Message[] {
  if (count === 0) return [...messages];
  const slots: number[] = [];
  for (let i = 1; i < messages.length - preserve; i += 1) {
    if (!messages[i]?.toolResults?.length) slots.push(i);
  }
  const perSlot = new Map<number, number>();
  for (let k = 0; k < count; k += 1) {
    const slot = slots[Math.floor((k * slots.length) / count)] ?? 1;
    perSlot.set(slot, (perSlot.get(slot) ?? 0) + 1);
  }
  const out: Message[] = [];
  let made = 0;
  messages.forEach((message, index) => {
    for (let k = 0; k < (perSlot.get(index) ?? 0); k += 1) {
      const filler = fillerCall(made);
      const id = `filler-${(made += 1)}`;
      out.push({ role: 'assistant', text: '', toolUses: [{ tool_use_id: id, tool: filler.tool, input: filler.input }] });
      out.push({ role: 'user', text: '', toolUses: [], toolResults: [{ tool_use_id: id, text: filler.text }] });
    }
    out.push(message);
  });
  return out;
}

/** The text a model reads from a transcript: message text, tool inputs, tool outputs. */
export function render(messages: readonly Message[]): string {
  const parts: string[] = [];
  for (const message of messages) {
    if (message.text) parts.push(message.text);
    for (const tool of message.toolUses) parts.push(JSON.stringify(tool.input));
    for (const result of message.toolResults ?? []) parts.push(result.text);
  }
  return parts.join('\n');
}

function survivors(messages: readonly Message[], facts: readonly Fact[]): boolean[] {
  const text = render(messages);
  return facts.map((fact) => text.includes(fact.needle));
}

/** Truncate every unpinned output to its head, keep every call: no model involved. */
function ruleBaseline(fixture: Fixture, preserve: number, headChars: number): Message[] {
  const calls = collectToolCalls(fixture.messages, preserve);
  const decisions: CallDecision[] = calls.map((call) => ({
    id: call.id,
    tool: call.tool,
    keepCall: 1,
    keepResult: call.pinned ? 1 : 0,
    action: call.pinned ? 'keep' : 'drop_result',
    reason: call.pinned ? 'pinned' : 'result_dropped',
  }));
  return applyDecisions(fixture.messages, decisions, calls, headChars);
}

function recordingAsker(
  inner: JevAsker,
  usage: Usage[],
  requests: { state: JevState; questions: JevQuestions }[],
): JevAsker {
  return {
    async ask(state, questions) {
      const started = Date.now();
      requests.push({ state, questions });
      const response = await inner.ask(state, questions);
      const raw = (response.usage ?? {}) as Record<string, unknown>;
      usage.push({
        ms: Date.now() - started,
        model: response.model,
        inputTokens: typeof raw.input_tokens === 'number' ? raw.input_tokens : undefined,
        outputTokens: typeof raw.output_tokens === 'number' ? raw.output_tokens : undefined,
        cost: typeof raw.cost === 'number' ? raw.cost : undefined,
      });
      return response;
    },
  };
}

function client(model: string): JevAsker {
  const openRouter = process.env.OPENROUTER_API_KEY;
  if (openRouter) return new JevClient({ apiKey: openRouter, baseUrl: OPENROUTER_URL, model });
  if (process.env.TYPESAFE_API_KEY) return new JevClient({ model });
  throw new Error('set OPENROUTER_API_KEY or TYPESAFE_API_KEY, or pass --dry');
}

function decisionLine(result: CompactResult): string {
  return result.decisions
    .filter((d) => d.reason !== 'pinned')
    .map((d) => `${d.id}:${d.tool}:${d.action}(${d.keepCall.toFixed(2)}/${d.keepResult.toFixed(2)})`)
    .join(' ');
}

function sum(values: readonly (number | undefined)[]): number {
  return values.reduce<number>((total, value) => total + (value ?? 0), 0);
}

function spread(values: readonly number[]): string {
  const sorted = [...values].sort((a, b) => a - b);
  const median = sorted[Math.floor((sorted.length - 1) / 2)];
  return `min ${sorted[0]} / median ${median} / max ${sorted[sorted.length - 1]}`;
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const fixtures = loadFixtures(args.fixtures);
  const asker = args.dry ? undefined : client(args.model);
  const report: unknown[] = [];
  let totalCost = 0;

  for (const loaded of fixtures) {
    const fixture: Fixture =
      args.pad === 0
        ? loaded
        : {
            ...loaded,
            name: `${loaded.name}+pad${args.pad}`,
            messages: padSession(loaded.messages, args.pad, loaded.preserveRecentMessages),
          };
    const options: CompactOptions = {
      preserveRecentMessages: fixture.preserveRecentMessages,
      ...args.set,
    };
    const resolved = resolveOptions(options);
    const calls = collectToolCalls(fixture.messages, resolved.preserveRecentMessages);
    const before = estimateTokens(render(fixture.messages));
    const rule = ruleBaseline(fixture, resolved.preserveRecentMessages, RULE_HEAD_CHARS);
    const ruleTokens = estimateTokens(render(rule));
    const ruleFacts = survivors(rule, fixture.facts);
    const state = fitState(fixture.messages, calls, resolved);

    console.log(
      `\n== ${fixture.name}: ${fixture.messages.length} messages, ${calls.length} calls, ${
        calls.filter((c) => !c.pinned).length
      } candidates`,
    );
    console.log(`before: ~${before} tokens; state ~${state.tokens} tokens (${state.stage})`);
    for (const head of new Set([RULE_HEAD_CHARS, resolved.truncateHeadChars])) {
      const baseline = ruleBaseline(fixture, resolved.preserveRecentMessages, head);
      const kept = survivors(baseline, fixture.facts);
      console.log(
        `rule baseline (truncate unpinned outputs to ${head} chars): ~${estimateTokens(
          render(baseline),
        )} tokens, facts ${kept.filter(Boolean).length}/${fixture.facts.length}${missing(fixture.facts, kept)}`,
      );
    }
    const runs: { tokens: number; facts: number; reduction: number }[] = [];
    if (!asker) {
      report.push({ fixture: fixture.name, before, ruleTokens, ruleFacts, state });
      continue;
    }
    for (let run = 1; run <= args.runs; run += 1) {
      const usage: Usage[] = [];
      const requests: { state: JevState; questions: JevQuestions }[] = [];
      const result = await compact(
        fixture.messages,
        recordingAsker(asker, usage, requests),
        options,
      );
      const after = estimateTokens(render(result.messages));
      const facts = survivors(result.messages, fixture.facts);
      const cost = sum(usage.map((u) => u.cost));
      const reduction = reductionRatio(result);
      const fallback = reduction < MIN_REDUCTION_RATIO;
      totalCost += cost;
      runs.push({ tokens: after, facts: facts.filter(Boolean).length, reduction });
      const { stats } = result;
      console.log(
        `run ${run}: ~${after} tokens after, facts ${facts.filter(Boolean).length}/${fixture.facts.length}${missing(
          fixture.facts,
          facts,
        )}; kept ${stats.kept}, truncated ${stats.resultsDropped}, dropped ${stats.callsDropped}, pinned ${
          stats.pinned
        }; state ~${stats.stateTokens} (${stats.stateStage}) in ${stats.requests} request(s); Jev in=${sum(
          usage.map((u) => u.inputTokens),
        )} out=${sum(usage.map((u) => u.outputTokens))} cost=$${cost.toFixed(5)} ${sum(
          usage.map((u) => u.ms),
        )}ms model=${usage[0]?.model ?? '?'}; reduction ${reduction.toFixed(3)}${
          fallback ? ` BELOW ${MIN_REDUCTION_RATIO}: the hook would fall back to the built-in summary` : ''
        }`,
      );
      console.log(`  ${decisionLine(result)}`);
      report.push({
        fixture: fixture.name,
        run,
        options,
        before,
        after,
        ruleTokens,
        facts: fixture.facts.map((fact, i) => ({ ...fact, survived: facts[i], rule: ruleFacts[i] })),
        decisions: result.decisions,
        stats,
        reduction,
        fallback,
        usage,
        requests: run === 1 ? requests : undefined,
      });
    }
    if (runs.length > 1) {
      console.log(
        `spread over ${runs.length} runs: tokens ${spread(runs.map((r) => r.tokens))}; facts ${spread(
          runs.map((r) => r.facts),
        )}`,
      );
    }
  }
  if (asker) console.log(`\ntotal Jev cost: $${totalCost.toFixed(5)}`);
  if (args.json) writeFileSync(args.json, JSON.stringify(report, null, 1));
}

function missing(facts: readonly Fact[], survived: readonly boolean[]): string {
  const lost = facts.filter((_, i) => !survived[i]).map((fact) => fact.name);
  return lost.length === 0 ? '' : ` (missing: ${lost.join('; ')})`;
}

await main();
