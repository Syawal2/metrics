import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { PromptRouter } from '../src/prompt/router.js';
import { AuditLog } from '../src/prompt/audit.js';

test('prompt router: executes tool calls (stubbed) and returns final content', async () => {
  let calls = 0;
  const llmClient = {
    chatCompletions: async ({ messages }) => {
      calls += 1;
      if (calls === 1) {
        // First response: request a tool.
        return {
          raw: null,
          message: { role: 'assistant', content: null },
          content: '',
          toolCalls: [
            { id: 'call_1', name: 'intercomswap_sc_info', arguments: {}, argumentsRaw: '{}', parseError: null },
          ],
          finishReason: 'tool_calls',
          usage: null,
        };
      }

      // Second response: final content.
      // Ensure tool result message exists in the input history.
      const hasToolMsg = messages.some((m) => m && m.role === 'tool');
      assert.equal(hasToolMsg, true);
      return {
        raw: null,
        message: { role: 'assistant', content: 'ok' },
        content: 'ok',
        toolCalls: [],
        finishReason: 'stop',
        usage: null,
      };
    },
  };

  const toolExecutor = {
    execute: async (name, args, { autoApprove }) => {
      assert.equal(autoApprove, true);
      assert.equal(name, 'intercomswap_sc_info');
      assert.deepEqual(args, {});
      return { type: 'info', ok: true };
    },
  };

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'intercomswap-prompt-'));
  const router = new PromptRouter({
    llmConfig: {
      baseUrl: 'http://stub/',
      apiKey: '',
      model: 'stub',
      maxTokens: 0,
      temperature: null,
      topP: null,
      topK: null,
      minP: null,
      repetitionPenalty: null,
      toolFormat: 'tools',
      timeoutMs: 1000,
    },
    llmClient,
    toolExecutor,
    auditDir: tmpDir,
    maxSteps: 4,
  });

  const out = await router.run({ prompt: 'hi', autoApprove: true });
  assert.equal(out.content, 'ok');
  assert.ok(out.session_id);
  assert.ok(Array.isArray(out.steps));
});

test('prompt router: seals secrets in tool results and allows secret handles to be reused', async () => {
  const PREIMAGE = 'a'.repeat(64);
  let calls = 0;

  const llmClient = {
    chatCompletions: async ({ messages }) => {
      calls += 1;

      if (calls === 1) {
        return {
          raw: null,
          message: { role: 'assistant', content: null },
          content: '',
          toolCalls: [{ id: 'call_1', name: 'intercomswap_ln_pay', arguments: { bolt11: 'lnbc1...' }, argumentsRaw: '{}', parseError: null }],
          finishReason: 'tool_calls',
          usage: null,
        };
      }

      if (calls === 2) {
        const toolMsg = messages.find((m) => m && m.role === 'tool');
        assert.ok(toolMsg, 'expected a tool message');
        assert.equal(typeof toolMsg.content, 'string');

        // Tool result must not leak the preimage to the model.
        assert.equal(toolMsg.content.includes(PREIMAGE), false);

        const parsed = JSON.parse(toolMsg.content);
        const handle = String(parsed.payment_preimage || '');
        assert.ok(handle.startsWith('secret:'), 'expected a secret handle in tool result');

        return {
          raw: null,
          message: { role: 'assistant', content: null },
          content: '',
          toolCalls: [
            {
              id: 'call_2',
              name: 'intercomswap_sol_escrow_claim',
              arguments: { preimage_hex: handle, mint: 'So11111111111111111111111111111111111111112' },
              argumentsRaw: '{}',
              parseError: null,
            },
          ],
          finishReason: 'tool_calls',
          usage: null,
        };
      }

      return {
        raw: null,
        message: { role: 'assistant', content: 'ok' },
        content: 'ok',
        toolCalls: [],
        finishReason: 'stop',
        usage: null,
      };
    },
  };

  const toolExecutor = {
    execute: async (name, args, { secrets }) => {
      if (name === 'intercomswap_ln_pay') return { payment_preimage: PREIMAGE, raw: { payment_preimage: PREIMAGE } };
      if (name === 'intercomswap_sol_escrow_claim') {
        assert.ok(String(args.preimage_hex).startsWith('secret:'));
        assert.ok(secrets && typeof secrets.get === 'function');
        assert.equal(secrets.get(args.preimage_hex), PREIMAGE);
        return { type: 'escrow_claimed', sig: 'stub' };
      }
      throw new Error(`unexpected tool: ${name}`);
    },
  };

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'intercomswap-prompt-'));
  const router = new PromptRouter({
    llmConfig: {
      baseUrl: 'http://stub/',
      apiKey: '',
      model: 'stub',
      maxTokens: 0,
      temperature: null,
      topP: null,
      topK: null,
      minP: null,
      repetitionPenalty: null,
      toolFormat: 'tools',
      timeoutMs: 1000,
    },
    llmClient,
    toolExecutor,
    auditDir: tmpDir,
    maxSteps: 6,
  });

  const out = await router.run({ prompt: 'do the thing', autoApprove: true });
  assert.equal(out.content, 'ok');
});

test('audit log: redacts sensitive keys', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'intercomswap-audit-'));
  const log = new AuditLog({ dir: tmpDir, sessionId: 'sess1' });

  log.write('tool_call', {
    token: 'secret',
    preimage_hex: 'a'.repeat(64),
    invite_b64: 'bbb',
    nested: { Authorization: 'Bearer abc' },
  });

  const text = fs.readFileSync(path.join(tmpDir, 'sess1.jsonl'), 'utf8');
  assert.ok(text.includes('<redacted>'));
  assert.equal(text.includes('secret'), false);
  assert.equal(text.includes('Bearer abc'), false);
});
