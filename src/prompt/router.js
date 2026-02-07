import { randomUUID } from 'node:crypto';

import { INTERCOMSWAP_SYSTEM_PROMPT } from './system.js';
import { INTERCOMSWAP_TOOLS } from './tools.js';
import { OpenAICompatibleClient } from './openaiClient.js';
import { AuditLog } from './audit.js';
import { SecretStore, isSecretHandle } from './secrets.js';

function nowMs() {
  return Date.now();
}

function safeJsonStringify(value) {
  try {
    return JSON.stringify(value);
  } catch (_e) {
    return JSON.stringify({ error: 'unserializable' });
  }
}

function normalizeToolResponseMessage({ toolFormat, toolCall, result }) {
  const content = typeof result === 'string' ? result : safeJsonStringify(result);
  if (toolFormat === 'functions') {
    return { role: 'function', name: toolCall.name, content };
  }
  // tools format
  return {
    role: 'tool',
    tool_call_id: toolCall.id || undefined,
    content,
  };
}

function isObject(v) {
  return v && typeof v === 'object' && !Array.isArray(v);
}

function shouldSealKey(key) {
  const k = String(key || '').toLowerCase();
  if (k.includes('preimage')) return true;
  if (k.includes('invite')) return true;
  if (k.includes('welcome')) return true;

  // Credentials/secrets.
  if (k.includes('api_key') || k.includes('apikey')) return true;
  if (k.includes('authorization') || k === 'auth') return true;
  if (k.includes('macaroon')) return true;
  if (k.includes('seed')) return true;
  if (k.includes('password')) return true;

  return false;
}

// Ensures tool results sent back to the model do not include secrets.
// Instead, secrets are replaced with opaque handles stored in the session SecretStore.
function sealToolResultForModel(value, secrets, { path = '' } = {}) {
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (typeof value === 'bigint') return value.toString();

  if (Array.isArray(value)) {
    return value.map((v, i) => sealToolResultForModel(v, secrets, { path: `${path}[${i}]` }));
  }

  if (isObject(value)) {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      const nextPath = path ? `${path}.${k}` : k;
      if (shouldSealKey(k) && v !== null && v !== undefined) {
        // Avoid double-wrapping if tool already returns a handle.
        if (typeof v === 'string' && isSecretHandle(v)) out[k] = v;
        else out[k] = secrets.put(v, { key: k, path: nextPath });
      } else {
        out[k] = sealToolResultForModel(v, secrets, { path: nextPath });
      }
    }
    return out;
  }

  // Fallback: attempt to serialize.
  return safeJsonStringify(value);
}

export class PromptRouter {
  constructor({
    llmConfig,
    llmClient = null,
    toolExecutor,
    auditDir = 'onchain/prompt/audit',
    maxSteps = 12,
  }) {
    if (!toolExecutor) throw new Error('PromptRouter requires toolExecutor');
    if (!llmConfig || typeof llmConfig !== 'object') throw new Error('PromptRouter requires llmConfig');
    if (!llmConfig.baseUrl) throw new Error('PromptRouter requires llmConfig.baseUrl');
    if (!llmConfig.model) throw new Error('PromptRouter requires llmConfig.model');

    this.toolExecutor = toolExecutor;
    this.auditDir = auditDir;
    this.maxSteps = maxSteps;

    const cfg = llmConfig;
    this.llmConfig = cfg;

    this.llmClient =
      llmClient ||
      new OpenAICompatibleClient({
        baseUrl: cfg.baseUrl,
        apiKey: cfg.apiKey,
        defaultModel: cfg.model,
        timeoutMs: cfg.timeoutMs,
        toolFormat: cfg.toolFormat,
      });

    this._sessions = new Map(); // sessionId -> { messages }
  }

  _getSession(sessionId) {
    const id = sessionId || randomUUID();
    if (!this._sessions.has(id)) {
      this._sessions.set(id, {
        messages: [{ role: 'system', content: INTERCOMSWAP_SYSTEM_PROMPT }],
        secrets: new SecretStore(),
      });
    }
    return { id, session: this._sessions.get(id) };
  }

  async run({
    prompt,
    sessionId = null,
    autoApprove = false,
    dryRun = false,
    maxSteps = null,
  }) {
    const p = String(prompt ?? '').trim();
    if (!p) throw new Error('prompt is required');

    const { id, session } = this._getSession(sessionId);
    const audit = new AuditLog({ dir: this.auditDir, sessionId: id });
    audit.write('prompt', { sessionId: id, prompt: p, autoApprove, dryRun });

    const tools = INTERCOMSWAP_TOOLS;
    const toolFormat = this.llmConfig.toolFormat === 'functions' ? 'functions' : 'tools';

    session.messages.push({ role: 'user', content: p });

    const steps = [];
    const max = maxSteps ?? this.maxSteps;

    for (let i = 0; i < max; i += 1) {
      const startedAt = nowMs();
      const llmOut = await this.llmClient.chatCompletions({
        messages: session.messages,
        tools,
        toolChoice: 'auto',
        maxTokens: this.llmConfig.maxTokens,
        temperature: this.llmConfig.temperature,
        topP: this.llmConfig.topP,
        topK: this.llmConfig.topK,
        minP: this.llmConfig.minP,
        repetitionPenalty: this.llmConfig.repetitionPenalty,
      });

      const llmStep = {
        type: 'llm',
        i,
        started_at: startedAt,
        duration_ms: nowMs() - startedAt,
        finish_reason: llmOut.finishReason,
        content: llmOut.content || '',
        tool_calls: llmOut.toolCalls,
      };
      steps.push(llmStep);
      audit.write('llm_response', llmStep);

      // If there are tool calls, execute them, append tool results, and loop.
      if (Array.isArray(llmOut.toolCalls) && llmOut.toolCalls.length > 0) {
        for (const call of llmOut.toolCalls) {
          if (!call || typeof call.name !== 'string') {
            throw new Error('Invalid tool call (missing name)');
          }
          if (call.parseError) {
            throw new Error(`Tool call arguments parse error for ${call.name}: ${call.parseError}`);
          }
          if (!call.arguments || typeof call.arguments !== 'object') {
            throw new Error(`Tool call missing arguments for ${call.name}`);
          }

          const toolStartedAt = nowMs();
          audit.write('tool_call', { name: call.name, arguments: call.arguments, dryRun, autoApprove });
          const toolResult = await this.toolExecutor.execute(call.name, call.arguments, {
            autoApprove,
            dryRun,
            secrets: session.secrets,
          });
          const toolResultForModel = sealToolResultForModel(toolResult, session.secrets);
          const toolStep = {
            type: 'tool',
            name: call.name,
            arguments: call.arguments,
            started_at: toolStartedAt,
            duration_ms: nowMs() - toolStartedAt,
            result: toolResultForModel,
          };
          steps.push(toolStep);
          audit.write('tool_result', toolStep);

          // Append tool result as a message so the model can continue.
          session.messages.push(normalizeToolResponseMessage({ toolFormat, toolCall: call, result: toolResultForModel }));
        }
        continue;
      }

      // Otherwise, we have a final assistant message.
      if (llmOut.message && typeof llmOut.message === 'object') session.messages.push(llmOut.message);
      audit.write('final', { content: llmOut.content || '' });
      return { session_id: id, content: llmOut.content || '', steps };
    }

    throw new Error(`Max steps exceeded (${max})`);
  }
}
