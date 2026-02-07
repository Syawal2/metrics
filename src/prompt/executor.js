import crypto from 'node:crypto';

import { PublicKey } from '@solana/web3.js';
import { createAssociatedTokenAccount, getAccount, getAssociatedTokenAddress } from '@solana/spl-token';

import { ScBridgeClient } from '../sc-bridge/client.js';
import { createUnsignedEnvelope, attachSignature, verifySignedEnvelope } from '../protocol/signedMessage.js';
import { validateSwapEnvelope } from '../swap/schema.js';
import { ASSET, KIND, PAIR } from '../swap/constants.js';
import { hashUnsignedEnvelope, sha256Hex } from '../swap/hash.js';
import { hashTermsEnvelope } from '../swap/terms.js';
import {
  createSignedInvite,
  normalizeInvitePayload,
  normalizeWelcomePayload,
} from '../sidechannel/capabilities.js';

import {
  lnConnect,
  lnDecodePay,
  lnFundChannel,
  lnGetInfo,
  lnInvoice,
  lnListFunds,
  lnNewAddress,
  lnPay,
  lnPayStatus,
  lnPreimageGet,
} from '../ln/client.js';

import { readSolanaKeypair } from '../solana/keypair.js';
import { SolanaRpcPool } from '../solana/rpcPool.js';
import {
  LN_USDT_ESCROW_PROGRAM_ID,
  createEscrowTx,
  claimEscrowTx,
  refundEscrowTx,
  getConfigState,
  getTradeConfigState,
  getEscrowState,
  initConfigTx,
  initTradeConfigTx,
  setConfigTx,
  setTradeConfigTx,
  withdrawFeesTx,
  withdrawTradeFeesTx,
} from '../solana/lnUsdtEscrowClient.js';
import { isSecretHandle } from './secrets.js';

function isObject(v) {
  return v && typeof v === 'object' && !Array.isArray(v);
}

function assertPlainObject(args, toolName) {
  if (!isObject(args)) throw new Error(`${toolName}: arguments must be an object`);
  const proto = Object.getPrototypeOf(args);
  if (proto !== Object.prototype && proto !== null) throw new Error(`${toolName}: arguments must be a plain object`);
}

function assertAllowedKeys(args, toolName, allowed) {
  const allow = new Set(allowed);
  for (const k of Object.keys(args)) {
    if (!allow.has(k)) throw new Error(`${toolName}: unexpected argument "${k}"`);
  }
}

function expectString(args, toolName, key, { min = 1, max = 10_000, pattern = null } = {}) {
  const v = args[key];
  if (typeof v !== 'string') throw new Error(`${toolName}: ${key} must be a string`);
  const s = v.trim();
  if (s.length < min) throw new Error(`${toolName}: ${key} must be at least ${min} chars`);
  if (s.length > max) throw new Error(`${toolName}: ${key} must be <= ${max} chars`);
  if (pattern && !pattern.test(s)) throw new Error(`${toolName}: ${key} is invalid`);
  return s;
}

function expectOptionalString(args, toolName, key, { min = 1, max = 10_000, pattern = null } = {}) {
  if (!(key in args) || args[key] === null || args[key] === undefined) return null;
  return expectString(args, toolName, key, { min, max, pattern });
}

function expectInt(args, toolName, key, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const v = args[key];
  if (!Number.isInteger(v)) throw new Error(`${toolName}: ${key} must be an integer`);
  if (v < min) throw new Error(`${toolName}: ${key} must be >= ${min}`);
  if (v > max) throw new Error(`${toolName}: ${key} must be <= ${max}`);
  return v;
}

function expectOptionalInt(args, toolName, key, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  if (!(key in args) || args[key] === null || args[key] === undefined) return null;
  return expectInt(args, toolName, key, { min, max });
}

function expectBool(args, toolName, key) {
  const v = args[key];
  if (typeof v !== 'boolean') throw new Error(`${toolName}: ${key} must be a boolean`);
  return v;
}

function normalizeChannelName(name) {
  const s = String(name || '').trim();
  if (!s) throw new Error('channel is required');
  if (s.length > 128) throw new Error('channel too long');
  if (/\s/.test(s)) throw new Error('channel must not contain whitespace');
  return s;
}

function normalizeHex32(hex, label = 'hex32') {
  const s = String(hex || '').trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(s)) throw new Error(`${label} must be 32-byte hex`);
  return s;
}

function normalizeHex33(hex, label = 'hex33') {
  const s = String(hex || '').trim().toLowerCase();
  if (!/^[0-9a-f]{66}$/.test(s)) throw new Error(`${label} must be 33-byte hex`);
  return s;
}

function normalizeBase58(s, label = 'base58') {
  const v = String(s || '').trim();
  if (!v) throw new Error(`${label} is required`);
  if (!/^[1-9A-HJ-NP-Za-km-z]+$/.test(v)) throw new Error(`${label} invalid`);
  return v;
}

function normalizeAtomicAmount(s, label = 'amount') {
  const v = String(s || '').trim();
  if (!/^[0-9]+$/.test(v)) throw new Error(`${label} must be a decimal string integer`);
  return v;
}

function stripSignature(envelope) {
  const { sig: _sig, signer: _signer, ...unsigned } = envelope || {};
  return unsigned;
}

function safeJsonStringify(value) {
  try {
    return JSON.stringify(value);
  } catch (_e) {
    return JSON.stringify({ error: 'unserializable tool result' });
  }
}

function decodeB64JsonMaybe(value) {
  if (value === null || value === undefined) return null;
  if (typeof value === 'object') return value;
  const s = String(value || '').trim();
  if (!s) return null;
  try {
    const decoded = Buffer.from(s, 'base64').toString('utf8');
    return JSON.parse(decoded);
  } catch (_e) {
    return null;
  }
}

function resolveSecretArg(secrets, value, { label, expectType = null } = {}) {
  if (typeof value !== 'string') return value;
  const s = value.trim();
  if (!isSecretHandle(s)) return value;
  if (!secrets || typeof secrets.get !== 'function') {
    throw new Error(`${label} is a secret handle but no secrets store was provided`);
  }
  const resolved = secrets.get(s);
  if (resolved === null || resolved === undefined) throw new Error(`Unknown ${label} secret handle`);
  if (expectType && typeof resolved !== expectType) throw new Error(`${label} secret handle has invalid type`);
  return resolved;
}

async function withScBridge({ url, token }, fn) {
  const sc = new ScBridgeClient({ url, token });
  try {
    await sc.connect();
    return await fn(sc);
  } finally {
    sc.close();
  }
}

async function signViaBridge(sc, payload) {
  const res = await sc.sign(payload);
  if (res.type !== 'signed') throw new Error(`Unexpected sign response: ${safeJsonStringify(res).slice(0, 200)}`);
  const signerHex = String(res.signer || '').trim().toLowerCase();
  const sigHex = String(res.sig || '').trim().toLowerCase();
  if (!signerHex || !sigHex) throw new Error('Signing failed (missing signer/sig)');
  return { signerHex, sigHex };
}

async function signSwapEnvelope(sc, unsignedEnvelope) {
  const { signerHex, sigHex } = await signViaBridge(sc, unsignedEnvelope);
  const signed = attachSignature(unsignedEnvelope, { signerPubKeyHex: signerHex, sigHex });
  const v = validateSwapEnvelope(signed);
  if (!v.ok) throw new Error(`Signed envelope invalid: ${v.error}`);
  return signed;
}

async function sendEnvelope(sc, channel, envelope) {
  const v = validateSwapEnvelope(envelope);
  if (!v.ok) throw new Error(`Envelope invalid: ${v.error}`);
  const res = await sc.send(channel, envelope);
  if (res.type === 'error') throw new Error(res.error || 'send failed');
  return res;
}

function requireApproval(toolName, autoApprove) {
  if (autoApprove) return;
  throw new Error(`${toolName}: blocked (auto_approve is false)`);
}

function computePaymentHashFromPreimage(preimageHex) {
  const bytes = Buffer.from(preimageHex, 'hex');
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

async function sendAndConfirm(connection, tx, commitment) {
  const sig = await connection.sendRawTransaction(tx.serialize());
  const conf = await connection.confirmTransaction(sig, commitment);
  if (conf?.value?.err) throw new Error(`Tx failed: ${JSON.stringify(conf.value.err)}`);
  return sig;
}

async function getOrCreateAta(connection, payerKeypair, owner, mint, commitment) {
  const ata = await getAssociatedTokenAddress(mint, owner, true);
  try {
    await getAccount(connection, ata, commitment);
    return ata;
  } catch (_e) {
    // createAssociatedTokenAccount will throw if ATA exists; retrying is fine.
  }
  await createAssociatedTokenAccount(connection, payerKeypair, mint, owner);
  return ata;
}

export class ToolExecutor {
  constructor({
    scBridge,
    ln,
    solana,
    receipts,
  }) {
    this.scBridge = scBridge; // { url, token }
    this.ln = ln; // config object passed to src/ln/client.js
    this.solana = solana; // { rpcUrls, commitment, programId, keypairPath, computeUnitLimit, computeUnitPriceMicroLamports }
    this.receipts = receipts; // { dbPath }

    this._solanaKeypair = null;
    this._solanaPool = null;
  }

  _pool() {
    if (this._solanaPool) return this._solanaPool;
    const urls = this.solana?.rpcUrls || 'http://127.0.0.1:8899';
    const commitment = this.solana?.commitment || 'confirmed';
    this._solanaPool = new SolanaRpcPool({ rpcUrls: urls, commitment });
    return this._solanaPool;
  }

  _programId() {
    const s = String(this.solana?.programId || '').trim();
    return s ? new PublicKey(s) : LN_USDT_ESCROW_PROGRAM_ID;
  }

  _commitment() {
    return String(this.solana?.commitment || 'confirmed').trim() || 'confirmed';
  }

  _computeBudget() {
    return {
      computeUnitLimit: this.solana?.computeUnitLimit ?? null,
      computeUnitPriceMicroLamports: this.solana?.computeUnitPriceMicroLamports ?? null,
    };
  }

  _requireSolanaSigner() {
    if (this._solanaKeypair) return this._solanaKeypair;
    const p = String(this.solana?.keypairPath || '').trim();
    if (!p) throw new Error('Solana signer not configured (set solana.keypair in prompt setup JSON)');
    this._solanaKeypair = readSolanaKeypair(p);
    return this._solanaKeypair;
  }

  async execute(toolName, args, { autoApprove = false, dryRun = false, secrets = null } = {}) {
    assertPlainObject(args ?? {}, toolName);

    // Read-only SC-Bridge
    if (toolName === 'intercomswap_sc_info') {
      assertAllowedKeys(args, toolName, []);
      return withScBridge(this.scBridge, (sc) => sc.info());
    }
    if (toolName === 'intercomswap_sc_stats') {
      assertAllowedKeys(args, toolName, []);
      return withScBridge(this.scBridge, (sc) => sc.stats());
    }
    if (toolName === 'intercomswap_sc_price_get') {
      assertAllowedKeys(args, toolName, []);
      return withScBridge(this.scBridge, (sc) => sc.priceGet());
    }

    // SC-Bridge mutations
    if (toolName === 'intercomswap_sc_join') {
      assertAllowedKeys(args, toolName, ['channel', 'invite_b64', 'welcome_b64']);
      requireApproval(toolName, autoApprove);
      const channel = normalizeChannelName(expectString(args, toolName, 'channel', { max: 128 }));
      const inviteRaw = expectOptionalString(args, toolName, 'invite_b64', { max: 16384 });
      const welcomeRaw = expectOptionalString(args, toolName, 'welcome_b64', { max: 16384 });
      const invite = inviteRaw !== null ? resolveSecretArg(secrets, inviteRaw, { label: 'invite_b64' }) : null;
      const welcome = welcomeRaw !== null ? resolveSecretArg(secrets, welcomeRaw, { label: 'welcome_b64' }) : null;
      if (dryRun) return { type: 'dry_run', tool: toolName, channel };
      return withScBridge(this.scBridge, (sc) => sc.join(channel, { invite, welcome }));
    }
    if (toolName === 'intercomswap_sc_leave') {
      assertAllowedKeys(args, toolName, ['channel']);
      requireApproval(toolName, autoApprove);
      const channel = normalizeChannelName(expectString(args, toolName, 'channel', { max: 128 }));
      if (dryRun) return { type: 'dry_run', tool: toolName, channel };
      return withScBridge(this.scBridge, (sc) => sc.leave(channel));
    }
    if (toolName === 'intercomswap_sc_open') {
      assertAllowedKeys(args, toolName, ['channel', 'via', 'invite_b64', 'welcome_b64']);
      requireApproval(toolName, autoApprove);
      const channel = normalizeChannelName(expectString(args, toolName, 'channel', { max: 128 }));
      const via = normalizeChannelName(expectString(args, toolName, 'via', { max: 128 }));
      const inviteRaw = expectOptionalString(args, toolName, 'invite_b64', { max: 16384 });
      const welcomeRaw = expectOptionalString(args, toolName, 'welcome_b64', { max: 16384 });
      const invite = inviteRaw !== null ? resolveSecretArg(secrets, inviteRaw, { label: 'invite_b64' }) : null;
      const welcome = welcomeRaw !== null ? resolveSecretArg(secrets, welcomeRaw, { label: 'welcome_b64' }) : null;
      if (dryRun) return { type: 'dry_run', tool: toolName, channel, via };
      return withScBridge(this.scBridge, (sc) => sc.open(channel, { via, invite, welcome }));
    }
    if (toolName === 'intercomswap_sc_send_text') {
      assertAllowedKeys(args, toolName, ['channel', 'text']);
      requireApproval(toolName, autoApprove);
      const channel = normalizeChannelName(expectString(args, toolName, 'channel', { max: 128 }));
      const text = expectString(args, toolName, 'text', { min: 1, max: 2000 });
      if (dryRun) return { type: 'dry_run', tool: toolName, channel };
      return withScBridge(this.scBridge, (sc) => sc.send(channel, text));
    }
    if (toolName === 'intercomswap_sc_send_json') {
      assertAllowedKeys(args, toolName, ['channel', 'json']);
      requireApproval(toolName, autoApprove);
      const channel = normalizeChannelName(expectString(args, toolName, 'channel', { max: 128 }));
      if (!('json' in args)) throw new Error(`${toolName}: json is required`);
      if (!isObject(args.json) && !Array.isArray(args.json)) throw new Error(`${toolName}: json must be an object/array`);
      const size = Buffer.byteLength(safeJsonStringify(args.json), 'utf8');
      if (size > 16_384) throw new Error(`${toolName}: json too large (${size} bytes)`);
      if (dryRun) return { type: 'dry_run', tool: toolName, channel };
      return withScBridge(this.scBridge, (sc) => sc.send(channel, args.json));
    }

    // RFQ / swap envelopes (signed + broadcast)
    if (toolName === 'intercomswap_rfq_post') {
      assertAllowedKeys(args, toolName, ['channel', 'trade_id', 'btc_sats', 'usdt_amount', 'valid_until_unix']);
      requireApproval(toolName, autoApprove);
      const channel = normalizeChannelName(expectString(args, toolName, 'channel', { max: 128 }));
      const tradeId = expectString(args, toolName, 'trade_id', { min: 1, max: 128, pattern: /^[A-Za-z0-9_.:-]+$/ });
      const btcSats = expectInt(args, toolName, 'btc_sats', { min: 1 });
      const usdtAmount = normalizeAtomicAmount(expectString(args, toolName, 'usdt_amount', { max: 64 }), 'usdt_amount');
      const validUntil = expectOptionalInt(args, toolName, 'valid_until_unix', { min: 1 });

      const unsigned = createUnsignedEnvelope({
        v: 1,
        kind: KIND.RFQ,
        tradeId,
        body: {
          pair: PAIR.BTC_LN__USDT_SOL,
          direction: `${ASSET.BTC_LN}->${ASSET.USDT_SOL}`,
          btc_sats: btcSats,
          usdt_amount: usdtAmount,
          ...(validUntil ? { valid_until_unix: validUntil } : {}),
        },
      });
      const rfqId = hashUnsignedEnvelope(unsigned);

      if (dryRun) return { type: 'dry_run', tool: toolName, channel, rfq_id: rfqId, unsigned };

      return withScBridge(this.scBridge, async (sc) => {
        const signed = await signSwapEnvelope(sc, unsigned);
        await sendEnvelope(sc, channel, signed);
        return { type: 'rfq_posted', channel, rfq_id: rfqId, envelope: signed };
      });
    }

    if (toolName === 'intercomswap_quote_post') {
      assertAllowedKeys(args, toolName, ['channel', 'trade_id', 'rfq_id', 'btc_sats', 'usdt_amount', 'valid_until_unix']);
      requireApproval(toolName, autoApprove);
      const channel = normalizeChannelName(expectString(args, toolName, 'channel', { max: 128 }));
      const tradeId = expectString(args, toolName, 'trade_id', { min: 1, max: 128, pattern: /^[A-Za-z0-9_.:-]+$/ });
      const rfqId = normalizeHex32(expectString(args, toolName, 'rfq_id', { min: 64, max: 64 }), 'rfq_id');
      const btcSats = expectInt(args, toolName, 'btc_sats', { min: 1 });
      const usdtAmount = normalizeAtomicAmount(expectString(args, toolName, 'usdt_amount', { max: 64 }), 'usdt_amount');
      const validUntil = expectInt(args, toolName, 'valid_until_unix', { min: 1 });

      const unsigned = createUnsignedEnvelope({
        v: 1,
        kind: KIND.QUOTE,
        tradeId,
        body: {
          rfq_id: rfqId,
          pair: PAIR.BTC_LN__USDT_SOL,
          direction: `${ASSET.BTC_LN}->${ASSET.USDT_SOL}`,
          btc_sats: btcSats,
          usdt_amount: usdtAmount,
          valid_until_unix: validUntil,
        },
      });
      const quoteId = hashUnsignedEnvelope(unsigned);
      if (dryRun) return { type: 'dry_run', tool: toolName, channel, quote_id: quoteId, unsigned };
      return withScBridge(this.scBridge, async (sc) => {
        const signed = await signSwapEnvelope(sc, unsigned);
        await sendEnvelope(sc, channel, signed);
        return { type: 'quote_posted', channel, quote_id: quoteId, envelope: signed };
      });
    }

    if (toolName === 'intercomswap_quote_accept') {
      assertAllowedKeys(args, toolName, ['channel', 'quote_envelope']);
      requireApproval(toolName, autoApprove);
      const channel = normalizeChannelName(expectString(args, toolName, 'channel', { max: 128 }));
      const quote = args.quote_envelope;
      if (!isObject(quote)) throw new Error(`${toolName}: quote_envelope must be an object`);
      const v = validateSwapEnvelope(quote);
      if (!v.ok) throw new Error(`${toolName}: invalid quote_envelope: ${v.error}`);
      if (quote.kind !== KIND.QUOTE) throw new Error(`${toolName}: quote_envelope.kind must be ${KIND.QUOTE}`);
      const sigOk = verifySignedEnvelope(quote);
      if (!sigOk.ok) throw new Error(`${toolName}: quote_envelope signature invalid: ${sigOk.error}`);

      const quoteId = hashUnsignedEnvelope(stripSignature(quote));
      const rfqId = String(quote.body.rfq_id);
      const tradeId = String(quote.trade_id);

      const unsigned = createUnsignedEnvelope({
        v: 1,
        kind: KIND.QUOTE_ACCEPT,
        tradeId,
        body: { rfq_id: rfqId, quote_id: quoteId },
      });
      if (dryRun) return { type: 'dry_run', tool: toolName, channel, unsigned };

      return withScBridge(this.scBridge, async (sc) => {
        const signed = await signSwapEnvelope(sc, unsigned);
        await sendEnvelope(sc, channel, signed);
        return { type: 'quote_accept_posted', channel, envelope: signed, rfq_id: rfqId, quote_id: quoteId };
      });
    }

    if (toolName === 'intercomswap_swap_invite_from_accept') {
      assertAllowedKeys(args, toolName, ['channel', 'accept_envelope', 'swap_channel', 'welcome_text', 'ttl_sec']);
      requireApproval(toolName, autoApprove);
      const channel = normalizeChannelName(expectString(args, toolName, 'channel', { max: 128 }));
      const accept = args.accept_envelope;
      if (!isObject(accept)) throw new Error(`${toolName}: accept_envelope must be an object`);
      const v = validateSwapEnvelope(accept);
      if (!v.ok) throw new Error(`${toolName}: invalid accept_envelope: ${v.error}`);
      if (accept.kind !== KIND.QUOTE_ACCEPT) throw new Error(`${toolName}: accept_envelope.kind must be ${KIND.QUOTE_ACCEPT}`);
      const sigOk = verifySignedEnvelope(accept);
      if (!sigOk.ok) throw new Error(`${toolName}: accept_envelope signature invalid: ${sigOk.error}`);

      const tradeId = String(accept.trade_id);
      const swapChannel = args.swap_channel ? normalizeChannelName(String(args.swap_channel)) : `swap:${tradeId}`;
      const welcomeText = expectString(args, toolName, 'welcome_text', { min: 1, max: 500 });
      const ttlSec = expectOptionalInt(args, toolName, 'ttl_sec', { min: 30, max: 60 * 60 * 24 * 7 });
      const inviteePubKey = String(accept.signer || '').trim().toLowerCase();
      if (!inviteePubKey) throw new Error(`${toolName}: accept envelope missing signer pubkey`);

      const rfqId = String(accept.body.rfq_id);
      const quoteId = String(accept.body.quote_id);

      if (dryRun) {
        return { type: 'dry_run', tool: toolName, channel, swap_channel: swapChannel, rfq_id: rfqId, quote_id: quoteId };
      }

      return withScBridge(this.scBridge, async (sc) => {
        const { signerHex: ownerPubKey } = await signViaBridge(sc, { _probe: 'swap_invite_owner' });
        const welcomePayload = normalizeWelcomePayload({
          channel: swapChannel,
          ownerPubKey,
          text: welcomeText,
          issuedAt: Date.now(),
          version: 1,
        });
        const { sigHex: welcomeSig } = await signViaBridge(sc, welcomePayload);
        const welcome = { payload: welcomePayload, sig: welcomeSig };

        const issuedAt = Date.now();
        const ttlMs = ttlSec !== null ? ttlSec * 1000 : 7 * 24 * 3600 * 1000;
        const invitePayload = normalizeInvitePayload({
          channel: swapChannel,
          inviteePubKey,
          inviterPubKey: ownerPubKey,
          inviterAddress: null,
          issuedAt,
          expiresAt: issuedAt + ttlMs,
          nonce: Math.random().toString(36).slice(2, 10),
          version: 1,
        });
        const { sigHex: inviteSig } = await signViaBridge(sc, invitePayload);
        const invite = createSignedInvite(invitePayload, () => inviteSig, { welcome });

        const unsigned = createUnsignedEnvelope({
          v: 1,
          kind: KIND.SWAP_INVITE,
          tradeId,
          body: {
            rfq_id: rfqId,
            quote_id: quoteId,
            swap_channel: swapChannel,
            owner_pubkey: ownerPubKey,
            invite,
            welcome,
          },
        });
        const signed = await signSwapEnvelope(sc, unsigned);
        await sendEnvelope(sc, channel, signed);

        return {
          type: 'swap_invite_posted',
          channel,
          swap_channel: swapChannel,
          owner_pubkey: ownerPubKey,
          envelope: signed,
          invite,
          welcome,
        };
      });
    }

    if (toolName === 'intercomswap_join_from_swap_invite') {
      assertAllowedKeys(args, toolName, ['swap_invite_envelope']);
      requireApproval(toolName, autoApprove);
      const inv = args.swap_invite_envelope;
      if (!isObject(inv)) throw new Error(`${toolName}: swap_invite_envelope must be an object`);
      const v = validateSwapEnvelope(inv);
      if (!v.ok) throw new Error(`${toolName}: invalid swap_invite_envelope: ${v.error}`);
      if (inv.kind !== KIND.SWAP_INVITE) throw new Error(`${toolName}: swap_invite_envelope.kind must be ${KIND.SWAP_INVITE}`);
      const sigOk = verifySignedEnvelope(inv);
      if (!sigOk.ok) throw new Error(`${toolName}: swap_invite_envelope signature invalid: ${sigOk.error}`);

      const swapChannel = String(inv.body.swap_channel || '').trim();
      if (!swapChannel) throw new Error(`${toolName}: swap_invite missing swap_channel`);

      const invite =
        inv.body.invite || (inv.body.invite_b64 ? decodeB64JsonMaybe(inv.body.invite_b64) : null);
      const welcome =
        inv.body.welcome || (inv.body.welcome_b64 ? decodeB64JsonMaybe(inv.body.welcome_b64) : null);
      if (!invite) throw new Error(`${toolName}: swap_invite missing invite`);

      if (dryRun) return { type: 'dry_run', tool: toolName, swap_channel: swapChannel };
      return withScBridge(this.scBridge, (sc) => sc.join(swapChannel, { invite, welcome }));
    }

    if (toolName === 'intercomswap_terms_post') {
      assertAllowedKeys(args, toolName, [
        'channel',
        'trade_id',
        'btc_sats',
        'usdt_amount',
        'sol_mint',
        'sol_recipient',
        'sol_refund',
        'sol_refund_after_unix',
        'ln_receiver_peer',
        'ln_payer_peer',
        'platform_fee_bps',
        'trade_fee_bps',
        'trade_fee_collector',
        'platform_fee_collector',
        'terms_valid_until_unix',
      ]);
      requireApproval(toolName, autoApprove);
      const channel = normalizeChannelName(expectString(args, toolName, 'channel', { max: 128 }));
      const tradeId = expectString(args, toolName, 'trade_id', { min: 1, max: 128, pattern: /^[A-Za-z0-9_.:-]+$/ });
      const btcSats = expectInt(args, toolName, 'btc_sats', { min: 1 });
      const usdtAmount = normalizeAtomicAmount(expectString(args, toolName, 'usdt_amount', { max: 64 }), 'usdt_amount');
      const solMint = normalizeBase58(expectString(args, toolName, 'sol_mint', { max: 64 }), 'sol_mint');
      const solRecipient = normalizeBase58(expectString(args, toolName, 'sol_recipient', { max: 64 }), 'sol_recipient');
      const solRefund = normalizeBase58(expectString(args, toolName, 'sol_refund', { max: 64 }), 'sol_refund');
      const solRefundAfter = expectInt(args, toolName, 'sol_refund_after_unix', { min: 1 });
      const lnReceiverPeer = normalizeHex32(expectString(args, toolName, 'ln_receiver_peer', { min: 64, max: 64 }), 'ln_receiver_peer');
      const lnPayerPeer = normalizeHex32(expectString(args, toolName, 'ln_payer_peer', { min: 64, max: 64 }), 'ln_payer_peer');
      const platformFeeBps = expectInt(args, toolName, 'platform_fee_bps', { min: 0, max: 500 });
      const tradeFeeBps = expectInt(args, toolName, 'trade_fee_bps', { min: 0, max: 1000 });
      const tradeFeeCollector = normalizeBase58(expectString(args, toolName, 'trade_fee_collector', { max: 64 }), 'trade_fee_collector');
      const platformFeeCollector = args.platform_fee_collector
        ? normalizeBase58(String(args.platform_fee_collector), 'platform_fee_collector')
        : null;
      const termsValidUntil = expectOptionalInt(args, toolName, 'terms_valid_until_unix', { min: 1 });

      const unsigned = createUnsignedEnvelope({
        v: 1,
        kind: KIND.TERMS,
        tradeId,
        body: {
          pair: PAIR.BTC_LN__USDT_SOL,
          direction: `${ASSET.BTC_LN}->${ASSET.USDT_SOL}`,
          btc_sats: btcSats,
          usdt_amount: usdtAmount,
          usdt_decimals: 6,
          sol_mint: solMint,
          sol_recipient: solRecipient,
          sol_refund: solRefund,
          sol_refund_after_unix: solRefundAfter,
          ln_receiver_peer: lnReceiverPeer,
          ln_payer_peer: lnPayerPeer,
          platform_fee_bps: platformFeeBps,
          trade_fee_bps: tradeFeeBps,
          trade_fee_collector: tradeFeeCollector,
          ...(platformFeeCollector ? { platform_fee_collector: platformFeeCollector } : {}),
          ...(termsValidUntil ? { terms_valid_until_unix: termsValidUntil } : {}),
        },
      });

      if (dryRun) return { type: 'dry_run', tool: toolName, channel, unsigned };

      return withScBridge(this.scBridge, async (sc) => {
        const signed = await signSwapEnvelope(sc, unsigned);
        await sendEnvelope(sc, channel, signed);
        return { type: 'terms_posted', channel, terms_hash: hashTermsEnvelope(signed), envelope: signed };
      });
    }

    if (toolName === 'intercomswap_terms_accept') {
      assertAllowedKeys(args, toolName, ['channel', 'trade_id', 'terms_hash_hex']);
      requireApproval(toolName, autoApprove);
      const channel = normalizeChannelName(expectString(args, toolName, 'channel', { max: 128 }));
      const tradeId = expectString(args, toolName, 'trade_id', { min: 1, max: 128, pattern: /^[A-Za-z0-9_.:-]+$/ });
      const termsHash = normalizeHex32(expectString(args, toolName, 'terms_hash_hex', { min: 64, max: 64 }), 'terms_hash');

      const unsigned = createUnsignedEnvelope({
        v: 1,
        kind: KIND.ACCEPT,
        tradeId,
        body: { terms_hash: termsHash },
      });
      if (dryRun) return { type: 'dry_run', tool: toolName, channel, unsigned };
      return withScBridge(this.scBridge, async (sc) => {
        const signed = await signSwapEnvelope(sc, unsigned);
        await sendEnvelope(sc, channel, signed);
        return { type: 'terms_accept_posted', channel, envelope: signed };
      });
    }

    // Lightning tools
    if (toolName === 'intercomswap_ln_info') {
      assertAllowedKeys(args, toolName, []);
      return lnGetInfo(this.ln);
    }
    if (toolName === 'intercomswap_ln_newaddr') {
      assertAllowedKeys(args, toolName, []);
      requireApproval(toolName, autoApprove);
      if (dryRun) return { type: 'dry_run', tool: toolName };
      return lnNewAddress(this.ln);
    }
    if (toolName === 'intercomswap_ln_listfunds') {
      assertAllowedKeys(args, toolName, []);
      return lnListFunds(this.ln);
    }
    if (toolName === 'intercomswap_ln_connect') {
      assertAllowedKeys(args, toolName, ['peer']);
      requireApproval(toolName, autoApprove);
      const peer = expectString(args, toolName, 'peer', { min: 10, max: 200 });
      if (dryRun) return { type: 'dry_run', tool: toolName, peer };
      return lnConnect(this.ln, { peer });
    }
    if (toolName === 'intercomswap_ln_fundchannel') {
      assertAllowedKeys(args, toolName, ['node_id', 'amount_sats', 'private']);
      requireApproval(toolName, autoApprove);
      const nodeId = normalizeHex33(expectString(args, toolName, 'node_id', { min: 66, max: 66 }), 'node_id');
      const amountSats = expectInt(args, toolName, 'amount_sats', { min: 1000 });
      const privateFlag = 'private' in args ? expectBool(args, toolName, 'private') : false;
      if (dryRun) return { type: 'dry_run', tool: toolName, node_id: nodeId, amount_sats: amountSats, private: privateFlag };
      // Note: privacy support is implementation-specific; we enforce the arg shape, but do not currently plumb it.
      return lnFundChannel(this.ln, { nodeId, amountSats, block: true });
    }
    if (toolName === 'intercomswap_ln_invoice_create') {
      assertAllowedKeys(args, toolName, ['amount_msat', 'label', 'description', 'expiry_sec']);
      requireApproval(toolName, autoApprove);
      const amountMsat = expectInt(args, toolName, 'amount_msat', { min: 1 });
      const label = expectString(args, toolName, 'label', { min: 1, max: 120 });
      const description = expectString(args, toolName, 'description', { min: 1, max: 500 });
      const expirySec = expectOptionalInt(args, toolName, 'expiry_sec', { min: 60, max: 60 * 60 * 24 * 7 });
      if (dryRun) return { type: 'dry_run', tool: toolName };
      return lnInvoice(this.ln, { amountMsat, label, description, expirySec });
    }
    if (toolName === 'intercomswap_ln_decodepay') {
      assertAllowedKeys(args, toolName, ['bolt11']);
      const bolt11 = expectString(args, toolName, 'bolt11', { min: 20, max: 8000 });
      return lnDecodePay(this.ln, { bolt11 });
    }
    if (toolName === 'intercomswap_ln_pay') {
      assertAllowedKeys(args, toolName, ['bolt11']);
      requireApproval(toolName, autoApprove);
      const bolt11 = expectString(args, toolName, 'bolt11', { min: 20, max: 8000 });
      if (dryRun) return { type: 'dry_run', tool: toolName };
      return lnPay(this.ln, { bolt11 });
    }
    if (toolName === 'intercomswap_ln_pay_status') {
      assertAllowedKeys(args, toolName, ['payment_hash_hex']);
      const paymentHashHex = normalizeHex32(expectString(args, toolName, 'payment_hash_hex', { min: 64, max: 64 }), 'payment_hash_hex');
      return lnPayStatus(this.ln, { paymentHashHex });
    }
    if (toolName === 'intercomswap_ln_preimage_get') {
      assertAllowedKeys(args, toolName, ['payment_hash_hex']);
      requireApproval(toolName, autoApprove);
      const paymentHashHex = normalizeHex32(expectString(args, toolName, 'payment_hash_hex', { min: 64, max: 64 }), 'payment_hash_hex');
      if (dryRun) return { type: 'dry_run', tool: toolName };
      return lnPreimageGet(this.ln, { paymentHashHex });
    }

    // Solana (read-only)
    if (toolName === 'intercomswap_sol_balance') {
      assertAllowedKeys(args, toolName, ['pubkey']);
      const pubkey = new PublicKey(normalizeBase58(expectString(args, toolName, 'pubkey', { max: 64 }), 'pubkey'));
      const commitment = this._commitment();
      return this._pool().call((connection) => connection.getBalance(pubkey, commitment), { label: 'sol_balance' });
    }

    if (toolName === 'intercomswap_sol_token_balance') {
      assertAllowedKeys(args, toolName, ['owner', 'mint']);
      const owner = new PublicKey(normalizeBase58(expectString(args, toolName, 'owner', { max: 64 }), 'owner'));
      const mint = new PublicKey(normalizeBase58(expectString(args, toolName, 'mint', { max: 64 }), 'mint'));
      const commitment = this._commitment();
      return this._pool().call(
        async (connection) => {
          const ata = await getAssociatedTokenAddress(mint, owner, true);
          try {
            const acct = await getAccount(connection, ata, commitment);
            return { ata: ata.toBase58(), amount: acct.amount.toString(), decimals: acct.decimals ?? null };
          } catch (_e) {
            return { ata: ata.toBase58(), amount: '0', decimals: null };
          }
        },
        { label: 'sol_token_balance' }
      );
    }

    if (toolName === 'intercomswap_sol_escrow_get') {
      assertAllowedKeys(args, toolName, ['payment_hash_hex', 'mint']);
      const paymentHashHex = normalizeHex32(expectString(args, toolName, 'payment_hash_hex', { min: 64, max: 64 }), 'payment_hash_hex');
      const programId = this._programId();
      const commitment = this._commitment();
      // mint is currently unused for lookup (escrow PDA depends only on payment hash).
      void normalizeBase58(expectString(args, toolName, 'mint', { max: 64 }), 'mint');
      return this._pool().call((connection) => getEscrowState(connection, paymentHashHex, programId, commitment), {
        label: 'sol_escrow_get',
      });
    }

    if (toolName === 'intercomswap_sol_config_get') {
      assertAllowedKeys(args, toolName, []);
      const programId = this._programId();
      const commitment = this._commitment();
      return this._pool().call((connection) => getConfigState(connection, programId, commitment), { label: 'sol_config_get' });
    }

    if (toolName === 'intercomswap_sol_trade_config_get') {
      assertAllowedKeys(args, toolName, ['fee_collector']);
      const feeCollector = new PublicKey(normalizeBase58(expectString(args, toolName, 'fee_collector', { max: 64 }), 'fee_collector'));
      const programId = this._programId();
      const commitment = this._commitment();
      return this._pool().call((connection) => getTradeConfigState(connection, feeCollector, programId, commitment), {
        label: 'sol_trade_config_get',
      });
    }

    // Solana mutations
    if (toolName === 'intercomswap_sol_config_set') {
      assertAllowedKeys(args, toolName, ['fee_bps', 'fee_collector']);
      requireApproval(toolName, autoApprove);
      const feeBps = expectInt(args, toolName, 'fee_bps', { min: 0, max: 500 });
      const feeCollector = new PublicKey(normalizeBase58(expectString(args, toolName, 'fee_collector', { max: 64 }), 'fee_collector'));
      if (dryRun) return { type: 'dry_run', tool: toolName, fee_bps: feeBps, fee_collector: feeCollector.toBase58() };

      const signer = this._requireSolanaSigner();
      const programId = this._programId();
      const commitment = this._commitment();
      const { computeUnitLimit, computeUnitPriceMicroLamports } = this._computeBudget();

      return this._pool().call(async (connection) => {
        // If config does not exist, init it.
        const current = await getConfigState(connection, programId, commitment);
        const build = current
          ? await setConfigTx({
              connection,
              authority: signer,
              feeCollector,
              feeBps,
              computeUnitLimit,
              computeUnitPriceMicroLamports,
              programId,
            })
          : await initConfigTx({
              connection,
              payer: signer,
              feeCollector,
              feeBps,
              computeUnitLimit,
              computeUnitPriceMicroLamports,
              programId,
            });
        const sig = await sendAndConfirm(connection, build.tx, commitment);
        return { type: current ? 'config_set' : 'config_init', sig, config_pda: build.configPda.toBase58() };
      }, { label: 'sol_config_set' });
    }

    if (toolName === 'intercomswap_sol_trade_config_set') {
      assertAllowedKeys(args, toolName, ['fee_bps', 'fee_collector']);
      requireApproval(toolName, autoApprove);
      const feeBps = expectInt(args, toolName, 'fee_bps', { min: 0, max: 1000 });
      const feeCollector = new PublicKey(normalizeBase58(expectString(args, toolName, 'fee_collector', { max: 64 }), 'fee_collector'));
      if (dryRun) return { type: 'dry_run', tool: toolName, fee_bps: feeBps, fee_collector: feeCollector.toBase58() };

      const signer = this._requireSolanaSigner();
      const programId = this._programId();
      const commitment = this._commitment();
      const { computeUnitLimit, computeUnitPriceMicroLamports } = this._computeBudget();

      return this._pool().call(async (connection) => {
        const current = await getTradeConfigState(connection, feeCollector, programId, commitment);
        const build = current
          ? await setTradeConfigTx({
              connection,
              authority: signer,
              feeCollector,
              feeBps,
              computeUnitLimit,
              computeUnitPriceMicroLamports,
              programId,
            })
          : await initTradeConfigTx({
              connection,
              payer: signer,
              feeCollector,
              feeBps,
              computeUnitLimit,
              computeUnitPriceMicroLamports,
              programId,
            });
        const sig = await sendAndConfirm(connection, build.tx, commitment);
        return { type: current ? 'trade_config_set' : 'trade_config_init', sig, trade_config_pda: build.tradeConfigPda.toBase58() };
      }, { label: 'sol_trade_config_set' });
    }

    if (toolName === 'intercomswap_sol_fees_withdraw') {
      assertAllowedKeys(args, toolName, ['mint', 'to', 'amount']);
      requireApproval(toolName, autoApprove);
      const mint = new PublicKey(normalizeBase58(expectString(args, toolName, 'mint', { max: 64 }), 'mint'));
      const to = new PublicKey(normalizeBase58(expectString(args, toolName, 'to', { max: 64 }), 'to'));
      const amountStr = normalizeAtomicAmount(expectString(args, toolName, 'amount', { max: 64 }), 'amount');
      const amount = BigInt(amountStr);
      if (dryRun) return { type: 'dry_run', tool: toolName };

      const signer = this._requireSolanaSigner();
      const programId = this._programId();
      const commitment = this._commitment();
      const { computeUnitLimit, computeUnitPriceMicroLamports } = this._computeBudget();

      return this._pool().call(async (connection) => {
        const toAta = await getOrCreateAta(connection, signer, to, mint, commitment);
        const build = await withdrawFeesTx({
          connection,
          feeCollector: signer,
          feeCollectorTokenAccount: toAta,
          mint,
          amount,
          computeUnitLimit,
          computeUnitPriceMicroLamports,
          programId,
        });
        const sig = await sendAndConfirm(connection, build.tx, commitment);
        return { type: 'fees_withdrawn', sig, fee_vault_ata: build.feeVaultAta.toBase58(), to_ata: toAta.toBase58() };
      }, { label: 'sol_fees_withdraw' });
    }

    if (toolName === 'intercomswap_sol_trade_fees_withdraw') {
      assertAllowedKeys(args, toolName, ['mint', 'to', 'amount']);
      requireApproval(toolName, autoApprove);
      const mint = new PublicKey(normalizeBase58(expectString(args, toolName, 'mint', { max: 64 }), 'mint'));
      const to = new PublicKey(normalizeBase58(expectString(args, toolName, 'to', { max: 64 }), 'to'));
      const amountStr = normalizeAtomicAmount(expectString(args, toolName, 'amount', { max: 64 }), 'amount');
      const amount = BigInt(amountStr);
      if (dryRun) return { type: 'dry_run', tool: toolName };

      const signer = this._requireSolanaSigner();
      const programId = this._programId();
      const commitment = this._commitment();
      const { computeUnitLimit, computeUnitPriceMicroLamports } = this._computeBudget();

      return this._pool().call(async (connection) => {
        const toAta = await getOrCreateAta(connection, signer, to, mint, commitment);
        const build = await withdrawTradeFeesTx({
          connection,
          feeCollector: signer,
          feeCollectorTokenAccount: toAta,
          mint,
          amount,
          computeUnitLimit,
          computeUnitPriceMicroLamports,
          programId,
        });
        const sig = await sendAndConfirm(connection, build.tx, commitment);
        return {
          type: 'trade_fees_withdrawn',
          sig,
          trade_config_pda: build.tradeConfigPda.toBase58(),
          fee_vault_ata: build.feeVaultAta.toBase58(),
          to_ata: toAta.toBase58(),
        };
      }, { label: 'sol_trade_fees_withdraw' });
    }

    if (toolName === 'intercomswap_sol_escrow_init') {
      assertAllowedKeys(args, toolName, [
        'payment_hash_hex',
        'mint',
        'amount',
        'recipient',
        'refund',
        'refund_after_unix',
        'platform_fee_bps',
        'trade_fee_bps',
        'trade_fee_collector',
        'platform_fee_collector',
      ]);
      requireApproval(toolName, autoApprove);
      const paymentHashHex = normalizeHex32(expectString(args, toolName, 'payment_hash_hex', { min: 64, max: 64 }), 'payment_hash_hex');
      const mint = new PublicKey(normalizeBase58(expectString(args, toolName, 'mint', { max: 64 }), 'mint'));
      const amountStr = normalizeAtomicAmount(expectString(args, toolName, 'amount', { max: 64 }), 'amount');
      const amount = BigInt(amountStr);
      const recipient = new PublicKey(normalizeBase58(expectString(args, toolName, 'recipient', { max: 64 }), 'recipient'));
      const refund = new PublicKey(normalizeBase58(expectString(args, toolName, 'refund', { max: 64 }), 'refund'));
      const refundAfterUnix = expectInt(args, toolName, 'refund_after_unix', { min: 1 });
      const platformFeeBps = expectInt(args, toolName, 'platform_fee_bps', { min: 0, max: 500 });
      const tradeFeeBps = expectInt(args, toolName, 'trade_fee_bps', { min: 0, max: 1000 });
      const tradeFeeCollector = new PublicKey(normalizeBase58(expectString(args, toolName, 'trade_fee_collector', { max: 64 }), 'trade_fee_collector'));
      // platform_fee_collector is validated in TERMS, but not required for escrow init (program uses config).
      void args.platform_fee_collector;

      if (dryRun) return { type: 'dry_run', tool: toolName, payment_hash_hex: paymentHashHex };

      const signer = this._requireSolanaSigner();
      const programId = this._programId();
      const commitment = this._commitment();
      const { computeUnitLimit, computeUnitPriceMicroLamports } = this._computeBudget();

      return this._pool().call(async (connection) => {
        const payerAta = await getOrCreateAta(connection, signer, signer.publicKey, mint, commitment);
        const build = await createEscrowTx({
          connection,
          payer: signer,
          payerTokenAccount: payerAta,
          mint,
          paymentHashHex,
          recipient,
          refund,
          refundAfterUnix,
          amount,
          expectedPlatformFeeBps: platformFeeBps,
          expectedTradeFeeBps: tradeFeeBps,
          tradeFeeCollector,
          computeUnitLimit,
          computeUnitPriceMicroLamports,
          programId,
        });
        const sig = await sendAndConfirm(connection, build.tx, commitment);
        return {
          type: 'escrow_inited',
          sig,
          program_id: programId.toBase58(),
          payment_hash_hex: paymentHashHex,
          escrow_pda: build.escrowPda.toBase58(),
          vault_ata: build.vault.toBase58(),
          platform_fee_vault_ata: build.platformFeeVaultAta.toBase58(),
          trade_config_pda: build.tradeConfigPda.toBase58(),
          trade_fee_vault_ata: build.tradeFeeVaultAta.toBase58(),
        };
      }, { label: 'sol_escrow_init' });
    }

    if (toolName === 'intercomswap_sol_escrow_claim') {
      assertAllowedKeys(args, toolName, ['preimage_hex', 'mint']);
      requireApproval(toolName, autoApprove);
      const preimageArg = expectString(args, toolName, 'preimage_hex', { min: 1, max: 200 });
      const preimageResolved = resolveSecretArg(secrets, preimageArg, { label: 'preimage_hex', expectType: 'string' });
      const preimageHex = normalizeHex32(preimageResolved, 'preimage_hex');
      const paymentHashHex = computePaymentHashFromPreimage(preimageHex);
      const mint = new PublicKey(normalizeBase58(expectString(args, toolName, 'mint', { max: 64 }), 'mint'));
      if (dryRun) return { type: 'dry_run', tool: toolName, payment_hash_hex: paymentHashHex };

      const signer = this._requireSolanaSigner();
      const programId = this._programId();
      const commitment = this._commitment();
      const { computeUnitLimit, computeUnitPriceMicroLamports } = this._computeBudget();

      return this._pool().call(async (connection) => {
        const escrow = await getEscrowState(connection, paymentHashHex, programId, commitment);
        if (!escrow) throw new Error('Escrow not found');
        if (!escrow.recipient.equals(signer.publicKey)) {
          throw new Error(`Recipient mismatch (escrow.recipient=${escrow.recipient.toBase58()})`);
        }
        if (!escrow.mint.equals(mint)) throw new Error(`Mint mismatch (escrow.mint=${escrow.mint.toBase58()})`);

        const tradeFeeCollector = escrow.tradeFeeCollector ?? escrow.feeCollector;
        if (!tradeFeeCollector) throw new Error('Escrow missing tradeFeeCollector');

        const recipientAta = await getOrCreateAta(connection, signer, signer.publicKey, mint, commitment);
        const build = await claimEscrowTx({
          connection,
          recipient: signer,
          recipientTokenAccount: recipientAta,
          mint,
          paymentHashHex,
          preimageHex,
          tradeFeeCollector,
          computeUnitLimit,
          computeUnitPriceMicroLamports,
          programId,
        });
        const sig = await sendAndConfirm(connection, build.tx, commitment);
        return { type: 'escrow_claimed', sig, escrow_pda: build.escrowPda.toBase58(), vault_ata: build.vault.toBase58() };
      }, { label: 'sol_escrow_claim' });
    }

    if (toolName === 'intercomswap_sol_escrow_refund') {
      assertAllowedKeys(args, toolName, ['payment_hash_hex', 'mint']);
      requireApproval(toolName, autoApprove);
      const paymentHashHex = normalizeHex32(expectString(args, toolName, 'payment_hash_hex', { min: 64, max: 64 }), 'payment_hash_hex');
      const mint = new PublicKey(normalizeBase58(expectString(args, toolName, 'mint', { max: 64 }), 'mint'));
      if (dryRun) return { type: 'dry_run', tool: toolName, payment_hash_hex: paymentHashHex };

      const signer = this._requireSolanaSigner();
      const programId = this._programId();
      const commitment = this._commitment();
      const { computeUnitLimit, computeUnitPriceMicroLamports } = this._computeBudget();

      return this._pool().call(async (connection) => {
        const escrow = await getEscrowState(connection, paymentHashHex, programId, commitment);
        if (!escrow) throw new Error('Escrow not found');
        if (!escrow.refund.equals(signer.publicKey)) {
          throw new Error(`Refund mismatch (escrow.refund=${escrow.refund.toBase58()})`);
        }
        if (!escrow.mint.equals(mint)) throw new Error(`Mint mismatch (escrow.mint=${escrow.mint.toBase58()})`);

        const refundAta = await getOrCreateAta(connection, signer, signer.publicKey, mint, commitment);
        const build = await refundEscrowTx({
          connection,
          refund: signer,
          refundTokenAccount: refundAta,
          mint,
          paymentHashHex,
          computeUnitLimit,
          computeUnitPriceMicroLamports,
          programId,
        });
        const sig = await sendAndConfirm(connection, build.tx, commitment);
        return { type: 'escrow_refunded', sig, escrow_pda: build.escrowPda.toBase58(), vault_ata: build.vault.toBase58() };
      }, { label: 'sol_escrow_refund' });
    }

    // Receipts (local-only)
    if (toolName === 'intercomswap_receipts_list' || toolName === 'intercomswap_receipts_show') {
      const { TradeReceiptsStore } = await import('../receipts/store.js');
      const dbPath = String(this.receipts?.dbPath || '').trim();
      if (!dbPath) throw new Error('receipts db not configured (set receipts.db in prompt setup JSON)');
      const store = TradeReceiptsStore.open({ dbPath });

      if (toolName === 'intercomswap_receipts_list') {
        assertAllowedKeys(args, toolName, []);
        return store.listTrades({ limit: 50 });
      }

      assertAllowedKeys(args, toolName, ['trade_id']);
      const tradeId = expectString(args, toolName, 'trade_id', { min: 1, max: 128 });
      return store.getTrade(tradeId);
    }

    throw new Error(`Unknown tool: ${toolName}`);
  }
}
