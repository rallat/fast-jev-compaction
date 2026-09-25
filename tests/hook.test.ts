import { describe, expect, it } from 'vitest';
import {
  compactGoal,
  compactRoute,
  compactSession,
  decisionLog,
  decisionLogLines,
  register,
  resolveHookConfig,
  summarize,
  toSessionMessages,
} from '../hooks/fast-jev.ts';
import { applyDecisions, collectToolCalls, decideCall, type Message } from '../src/index.js';

type SessionMessage = Message & { handle?: string };

function message(role: Message['role'], text: string, extra: Partial<SessionMessage> = {}): SessionMessage {
  return { role, text, toolUses: [], ...extra };
}

function call(id: string, tool: string, input: Record<string, unknown>, text: string): SessionMessage {
  return message('assistant', '', {
    toolUses: [{ tool_use_id: id, tool, input, text }],
    handle: `h-${id}`,
  });
}

function result(id: string, text: string, isError = false): SessionMessage {
  return message('user', '', { toolResults: [{ tool_use_id: id, text, isError }], handle: `r-${id}` });
}

const fileA = 'export const a = 1;\n'.repeat(50);

function transcript(): SessionMessage[] {
  return [
    message('user', 'Fix the failing test.', { handle: 'h-0' }),
    call('tool-1', 'Read', { file_path: 'src/a.ts' }, fileA),
    result('tool-1', fileA),
    call('tool-2', 'Bash', { command: 'npm test' }, 'FAIL'),
    result('tool-2', 'FAIL b.test.ts: expected 2 to be 3', true),
    message('assistant', 'Fixing now.', { handle: 'h-5' }),
    message('user', 'go ahead', { handle: 'h-6' }),
  ];
}

function jevFetch(answer: (name: string) => number, bodies: string[] = []) {
  return async (_url: string, init?: { body?: string }) => {
    bodies.push(init?.body ?? '');
    const { questions } = JSON.parse(init?.body ?? '{}') as { questions: Record<string, unknown> };
    const answers = Object.fromEntries(
      Object.keys(questions).map((key) => [key, { type: 'noul', noul: answer(key) }]),
    );
    return { status: 200, ok: true, text: JSON.stringify({ answers }) };
  };
}

describe('hook config', () => {
  it('reads userConfig values and falls back to defaults', () => {
    expect(resolveHookConfig({})).toEqual({
      compactAtPercent: 60,
      minReductionRatio: 0.25,
      model: 'jev-latest',
      compactTriggers: ['manual', 'auto', 'plugin'],
      compactSubagents: false,
    });
    expect(
      resolveHookConfig({ apiKey: 'k', keepThreshold: 0.3, maxStateTokens: 1000, model: 'jev-x', goal: 'g', compactAtPercent: 'no' }),
    ).toEqual({
      apiKey: 'k',
      keepThreshold: 0.3,
      maxStateTokens: 1000,
      model: 'jev-x',
      goal: 'g',
      compactAtPercent: 60,
      minReductionRatio: 0.25,
      compactTriggers: ['manual', 'auto', 'plugin'],
      compactSubagents: false,
    });
  });

  it('reads compactTriggers as a comma list or array and compactSubagents as a boolean', () => {
    expect(resolveHookConfig({ compactTriggers: ' manual , precompute,bogus', compactSubagents: true })).toMatchObject({
      compactTriggers: ['manual', 'precompute'],
      compactSubagents: true,
    });
    expect(resolveHookConfig({ compactTriggers: ['auto'] }).compactTriggers).toEqual(['auto']);
    expect(resolveHookConfig({ compactTriggers: 'none' }).compactTriggers).toEqual([]);
    expect(resolveHookConfig({ compactSubagents: 'yes' }).compactSubagents).toBe(false);
  });

  it('matches trigger names in any case and keeps the defaults when none is recognised', () => {
    expect(resolveHookConfig({ compactTriggers: 'Manual, AUTO' }).compactTriggers).toEqual([
      'manual',
      'auto',
    ]);
    expect(resolveHookConfig({ compactTriggers: ' None ' }).compactTriggers).toEqual([]);
    expect(resolveHookConfig({ compactTriggers: 'manaul,atuo' }).compactTriggers).toEqual([
      'manual',
      'auto',
      'plugin',
    ]);
  });
});

describe('compaction routing', () => {
  const config = resolveHookConfig({});

  it('runs Jev on manual, auto and plugin compactions of the main conversation', () => {
    for (const trigger of ['manual', 'auto', 'plugin'] as const) {
      expect(compactRoute({ trigger }, config)).toBe('jev');
    }
  });

  it('vetoes precompute while fast-jev handles auto, so no core summary is precomputed', () => {
    expect(compactRoute({ trigger: 'precompute' }, config)).toBe('skip');
    const manualOnly = resolveHookConfig({ compactTriggers: 'manual' });
    expect(compactRoute({ trigger: 'precompute' }, manualOnly)).toBe('core');
    expect(compactRoute({ trigger: 'auto' }, manualOnly)).toBe('core');
    const withPrecompute = resolveHookConfig({ compactTriggers: 'auto,precompute' });
    expect(compactRoute({ trigger: 'precompute' }, withPrecompute)).toBe('jev');
  });

  it('leaves subagent transcripts to core unless compactSubagents is set', () => {
    expect(compactRoute({ trigger: 'auto', agentId: 'a1' }, config)).toBe('core');
    expect(compactRoute({ trigger: 'precompute', agentId: 'a1' }, config)).toBe('core');
    const subagents = resolveHookConfig({ compactSubagents: true });
    expect(compactRoute({ trigger: 'auto', agentId: 'a1' }, subagents)).toBe('jev');
  });

  it('adds /compact instructions to the goal Jev sees', () => {
    const messages = transcript();
    expect(compactGoal(messages, undefined, undefined)).toBeUndefined();
    expect(compactGoal(messages, 'ship it', '  ')).toBe('ship it');
    expect(compactGoal(messages, 'ship it', 'keep the test output')).toBe(
      'ship it\nCompaction instructions: keep the test output',
    );
    expect(compactGoal(messages, undefined, 'keep the test output')).toBe(
      'Fix the failing test.\ngo ahead\nCompaction instructions: keep the test output',
    );
  });
});

type Handler = (...args: any[]) => Promise<unknown>;

/** Drives `register` with a fake `on` and a fake `$`, recording what the hook touched. */
function harness(options: Record<string, unknown> = {}, percent = 0) {
  const handlers = new Map<string, Handler>();
  const bodies: string[] = [];
  const logs: string[] = [];
  const answer = jevFetch((name) => (name === 'call_t2' || name === 'result_t2' ? 0.9 : 0.1), bodies);
  const calls = { fetch: 0, usage: 0, compact: 0 };
  const $ = {
    http: {
      fetch: async (url: string, init?: { body?: string }) => {
        calls.fetch++;
        return answer(url, init);
      },
    },
    env: { get: async (name: string) => (name === 'TYPESAFE_API_KEY' ? 'k' : undefined) },
    settings: { read: async () => ({}) },
    ui: { log: (text: string) => logs.push(text), toast: () => {} },
    session: {
      usage: async () => {
        calls.usage++;
        return { context: { percent } };
      },
      compact: async () => {
        calls.compact++;
        return { messages: [] };
      },
    },
  };
  register(((event: string, handler: Handler) => handlers.set(event, handler)) as never, {
    preserveRecentMessages: 1,
    ...options,
  } as never);
  const nextCalls: unknown[] = [];
  const next = async (event: unknown) => {
    nextCalls.push(event);
    return { messages: ['core'] };
  };
  const fire = (name: string, event: Record<string, unknown>) => handlers.get(name)!($, event, next);
  return { fire, calls, bodies, logs, nextCalls };
}

describe('registered hooks', () => {
  it('compacts a manual /compact through Jev and returns the pruned messages', async () => {
    const h = harness();
    const out = (await h.fire('session.compact', { trigger: 'manual', messages: transcript() })) as {
      messages: SessionMessage[];
    };
    expect(h.calls.fetch).toBe(1);
    expect(h.nextCalls).toHaveLength(0);
    expect(out.messages.map((m) => m.handle)).toEqual(['h-0', 'h-tool-2', 'r-tool-2', 'h-5', 'h-6']);
  });

  it('passes /compact instructions into the Jev goal', async () => {
    const h = harness();
    await h.fire('session.compact', { trigger: 'manual', instructions: 'keep the test output', messages: transcript() });
    expect(JSON.parse(h.bodies[0]!).state.goal).toMatch(/Compaction instructions: keep the test output$/);
  });

  it('vetoes precompute without a Jev call', async () => {
    const h = harness();
    const event = { trigger: 'precompute', messages: transcript() };
    const out = (await h.fire('session.compact', event)) as { skip?: string };
    expect(h.calls.fetch).toBe(0);
    expect(h.nextCalls).toHaveLength(0);
    expect(out.skip).toEqual(expect.any(String));
  });

  it('hands precompute to core when auto is not a fast-jev trigger', async () => {
    const h = harness({ compactTriggers: 'manual' });
    const event = { trigger: 'precompute', messages: transcript() };
    await h.fire('session.compact', event);
    expect(h.calls.fetch).toBe(0);
    expect(h.nextCalls).toEqual([event]);
  });

  it('hands a subagent transcript to core without a Jev call', async () => {
    const h = harness();
    const event = { trigger: 'auto', agentId: 'a1', messages: transcript() };
    const out = await h.fire('session.compact', event);
    expect(h.calls.fetch).toBe(0);
    expect(h.nextCalls).toEqual([event]);
    expect(out).toEqual({ messages: ['core'] });
  });

  it('compacts subagent transcripts and precompute when configured to', async () => {
    const h = harness({ compactSubagents: true, compactTriggers: 'auto,precompute' });
    await h.fire('session.compact', { trigger: 'auto', agentId: 'a1', messages: transcript() });
    await h.fire('session.compact', { trigger: 'precompute', messages: transcript() });
    expect(h.calls.fetch).toBe(2);
    expect(h.nextCalls).toHaveLength(0);
  });

  it('hands a manual compaction to core when manual is not a fast-jev trigger', async () => {
    const h = harness({ compactTriggers: 'auto' });
    const event = { trigger: 'manual', messages: transcript() };
    await h.fire('session.compact', event);
    expect(h.calls.fetch).toBe(0);
    expect(h.nextCalls).toEqual([event]);
  });

  it('auto-compacts the main conversation at the threshold but ignores subagent turns', async () => {
    const h = harness({}, 90);
    await h.fire('turn.complete', { agentId: 'a1', reason: 'answer' });
    expect(h.calls).toMatchObject({ usage: 0, compact: 0 });
    expect(h.nextCalls).toHaveLength(1);
    await h.fire('turn.complete', { reason: 'answer' });
    expect(h.calls).toMatchObject({ usage: 1, compact: 1 });
    expect(h.nextCalls).toHaveLength(2);
  });
});

describe('session message mapping', () => {
  it('returns the engine objects for untouched messages and handle-less copies for rebuilt ones', () => {
    const messages = transcript();
    const calls = collectToolCalls(messages, 0);
    const decisions = [
      decideCall(calls[0]!, { keepCall: 0.9, keepResult: 0.1 }, { keepThreshold: 0.5 }),
      decideCall(calls[1]!, { keepCall: 0.9, keepResult: 0.9 }, { keepThreshold: 0.5 }),
    ];
    messages[1]!.toolUses[0]!.text = 'x'.repeat(2000);
    messages[2]!.toolResults![0]!.text = 'x'.repeat(2000);
    const out = toSessionMessages(messages, applyDecisions(messages, decisions, calls, 300));
    expect(out).toHaveLength(messages.length);
    expect(out[0]).toBe(messages[0]);
    expect(out[1]?.handle).toBeUndefined();
    expect(out[1]?.toolUses[0]?.text).toMatch(
      new RegExp(`^${'x'.repeat(300)}\\n\\[fast-jev-compaction truncated 1700 chars`),
    );
    expect(out[2]?.handle).toBeUndefined();
    expect(out[2]?.toolResults?.[0]?.text).toMatch(
      new RegExp(`^${'x'.repeat(300)}\\n\\[fast-jev-compaction truncated 1700 chars`),
    );
    expect(out[2]?.toolResults?.[0]).toMatchObject({ tool_use_id: 'tool-1', isError: false });
    expect(out[3]).toBe(messages[3]);
    expect(out[4]).toBe(messages[4]);
  });

  it('preserves short dropped-result messages and their handles', () => {
    const messages = transcript();
    messages[1]!.toolUses[0]!.text = 'y'.repeat(100);
    messages[2]!.toolResults![0]!.text = 'y'.repeat(100);
    const calls = collectToolCalls(messages, 0);
    const decisions = [
      decideCall(calls[0]!, { keepCall: 0.9, keepResult: 0.1 }, { keepThreshold: 0.5 }),
      decideCall(calls[1]!, { keepCall: 0.9, keepResult: 0.9 }, { keepThreshold: 0.5 }),
    ];
    const out = toSessionMessages(messages, applyDecisions(messages, decisions, calls, 300));
    expect(out[1]).toBe(messages[1]);
    expect(out[2]).toBe(messages[2]);
  });
});

describe('compactSession', () => {
  it('runs the library over the engine fetch and reports the outcome', async () => {
    const bodies: string[] = [];
    const config = { ...resolveHookConfig({ preserveRecentMessages: 1 }), apiKey: 'k', model: 'jev-x' };
    const { result: output, messages } = await compactSession(
      transcript(),
      config,
      jevFetch((name) => (name === 'call_t2' || name === 'result_t2' ? 0.9 : 0.1), bodies),
    );
    expect(bodies).toHaveLength(1);
    expect(JSON.parse(bodies[0]!).model).toBe('jev-x');
    expect(output.decisions.map((d) => d.action)).toEqual(['drop_call', 'keep']);
    expect(messages.map((m) => m.handle)).toEqual(['h-0', 'h-tool-2', 'r-tool-2', 'h-5', 'h-6']);
    expect(summarize(output)).toMatch(/^\d+% reduction; 1 kept, 1 call_dropped; state ~\d+ tokens \(full\) in 1 request\(s\)$/);
    expect(decisionLog(output)).toBe('t1:Read:drop_call/call=0.10/result=0.10 t2:Bash:keep/call=0.90/result=0.90');
    expect(decisionLogLines(output)).toEqual([`decisions: ${decisionLog(output)}`]);
  });

  it('splits a long decision log into ui.log lines under the host limit', async () => {
    const config = { ...resolveHookConfig({ preserveRecentMessages: 1 }), apiKey: 'k' };
    const { result: output } = await compactSession(transcript(), config, jevFetch(() => 0.1));
    const lines = decisionLogLines(output, 60);
    expect(lines).toEqual([
      'decisions (1/2): t1:Read:drop_call/call=0.10/result=0.10',
      'decisions (2/2): t2:Bash:drop_call/call=0.10/result=0.10',
    ]);
    expect(lines.every((line) => line.length <= 60)).toBe(true);
    expect(decisionLogLines({ ...output, decisions: [] })).toEqual(['decisions: (none)']);
  });

  it('throws on a missing key and on failed requests so the hook falls back', async () => {
    const config = resolveHookConfig({ preserveRecentMessages: 1 });
    await expect(compactSession(transcript(), config, jevFetch(() => 0))).rejects.toThrow(/TYPESAFE_API_KEY/);
    await expect(
      compactSession(transcript(), { ...config, apiKey: 'k' }, async () => ({ status: 500, ok: false, text: 'x' })),
    ).rejects.toThrow(/500/);
  });
});
