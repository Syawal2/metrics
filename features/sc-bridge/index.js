import Feature from 'trac-peer/src/artifacts/feature.js';
import b4a from 'b4a';
import ws from 'bare-ws';

const normalizeText = (value) => {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') return value;
  try {
    return JSON.stringify(value);
  } catch (_e) {
    return String(value);
  }
};

const parseFilter = (raw) => {
  if (!raw) return [];
  return String(raw)
    .split('|')
    .map((group) =>
      group
        .trim()
        .split(/[+,\s]+/)
        .map((word) => word.trim())
        .filter(Boolean)
        .map((word) => word.toLowerCase())
    )
    .filter((group) => group.length > 0);
};

const matchesFilter = (filter, text) => {
  if (!filter || filter.length === 0) return true;
  const haystack = text.toLowerCase();
  return filter.some((group) => group.every((word) => haystack.includes(word)));
};

class ScBridge extends Feature {
  constructor(peer, config = {}) {
    super(peer, config);
    this.key = 'sc-bridge';
    this.sidechannel = null;
    this.server = null;
    this.started = false;
    this.clients = new Set();

    this.host = typeof config.host === 'string' ? config.host : '127.0.0.1';
    this.port = Number.isSafeInteger(config.port) ? config.port : 49222;
    this.token = typeof config.token === 'string' && config.token.length > 0 ? config.token : null;
    this.debug = config.debug === true;

    this.defaultFilterRaw = typeof config.filter === 'string' ? config.filter : '';
    this.defaultFilter = parseFilter(this.defaultFilterRaw);
    this.filterChannels = Array.isArray(config.filterChannels)
      ? new Set(config.filterChannels.map((c) => String(c)))
      : null;
  }

  attachSidechannel(sidechannel) {
    this.sidechannel = sidechannel;
  }

  _broadcastToClient(client, payload) {
    try {
      const data = JSON.stringify(payload);
      client.socket.write(data);
    } catch (_e) {}
  }

  _shouldEmit(client, channel, messageText) {
    if (client.channels && client.channels.size > 0 && !client.channels.has(channel)) {
      return false;
    }
    const filterApplies = this.filterChannels ? this.filterChannels.has(channel) : true;
    if (!filterApplies) return true;
    return matchesFilter(client.filter, messageText);
  }

  handleSidechannelMessage(channel, payload, _connection) {
    const messageText = normalizeText(payload?.message ?? payload);
    const event = {
      type: 'sidechannel_message',
      channel,
      id: payload?.id ?? null,
      from: payload?.from ?? null,
      origin: payload?.origin ?? null,
      relayedBy: payload?.relayedBy ?? null,
      ttl: payload?.ttl ?? null,
      ts: payload?.ts ?? Date.now(),
      message: payload?.message ?? payload,
    };
    if (this.debug) {
      console.log(`[sc-bridge] recv ${channel}:`, messageText);
    }
    if (this.debug) {
      console.log(`[sc-bridge] clients ${this.clients.size}`);
    }
    for (const client of this.clients) {
      if (!client.ready) continue;
      if (!this._shouldEmit(client, channel, messageText)) {
        if (this.debug) console.log('[sc-bridge] filtered');
        continue;
      }
      if (this.debug) console.log('[sc-bridge] emit');
      this._broadcastToClient(client, event);
    }
  }

  _sendError(client, error) {
    this._broadcastToClient(client, { type: 'error', error });
  }

  _handleClientMessage(client, message) {
    if (!message || typeof message !== 'object') {
      this._sendError(client, 'Invalid message.');
      return;
    }
    if (this.token && !client.authed) {
      if (message.type === 'auth' && message.token === this.token) {
        client.authed = true;
        this._broadcastToClient(client, { type: 'auth_ok' });
        return;
      }
      this._sendError(client, 'Unauthorized.');
      return;
    }

    switch (message.type) {
      case 'ping':
        this._broadcastToClient(client, { type: 'pong', ts: Date.now() });
        return;
      case 'set_filter': {
        client.filter = parseFilter(message.filter || '');
        this._broadcastToClient(client, { type: 'filter_set', filter: message.filter || '' });
        return;
      }
      case 'clear_filter': {
        client.filter = [];
        this._broadcastToClient(client, { type: 'filter_set', filter: '' });
        return;
      }
      case 'subscribe': {
        const channels = Array.isArray(message.channels)
          ? message.channels
          : message.channel
            ? [message.channel]
            : [];
        if (!client.channels) client.channels = new Set();
        for (const ch of channels) client.channels.add(String(ch));
        this._broadcastToClient(client, { type: 'subscribed', channels: Array.from(client.channels) });
        return;
      }
      case 'unsubscribe': {
        const channels = Array.isArray(message.channels)
          ? message.channels
          : message.channel
            ? [message.channel]
            : [];
        if (!client.channels) client.channels = new Set();
        for (const ch of channels) client.channels.delete(String(ch));
        this._broadcastToClient(client, { type: 'subscribed', channels: Array.from(client.channels) });
        return;
      }
      case 'send': {
        if (!this.sidechannel) {
          this._sendError(client, 'Sidechannel not ready.');
          return;
        }
        const channel = String(message.channel || '').trim();
        if (!channel) {
          this._sendError(client, 'Missing channel.');
          return;
        }
        const payload = message.message;
        this.sidechannel.broadcast(channel, payload);
        this._broadcastToClient(client, { type: 'sent', channel });
        return;
      }
      case 'join': {
        if (!this.sidechannel) {
          this._sendError(client, 'Sidechannel not ready.');
          return;
        }
        const channel = String(message.channel || '').trim();
        if (!channel) {
          this._sendError(client, 'Missing channel.');
          return;
        }
        this.sidechannel.addChannel(channel).catch(() => {});
        this._broadcastToClient(client, { type: 'joined', channel });
        return;
      }
      case 'open': {
        if (!this.sidechannel) {
          this._sendError(client, 'Sidechannel not ready.');
          return;
        }
        const channel = String(message.channel || '').trim();
        if (!channel) {
          this._sendError(client, 'Missing channel.');
          return;
        }
        const via = message.via ? String(message.via) : null;
        this.sidechannel.requestOpen(channel, via);
        this._broadcastToClient(client, { type: 'open_requested', channel, via: via || null });
        return;
      }
      case 'stats': {
        if (!this.sidechannel) {
          this._sendError(client, 'Sidechannel not ready.');
          return;
        }
        const channels = Array.from(this.sidechannel.channels.keys());
        const connectionCount = this.sidechannel.connections.size;
        this._broadcastToClient(client, { type: 'stats', channels, connectionCount });
        return;
      }
      default:
        this._sendError(client, `Unknown type: ${message.type}`);
    }
  }

  _handleSocketData(client, data) {
    let text = '';
    if (typeof data === 'string') text = data;
    else if (b4a.isBuffer(data)) text = b4a.toString(data, 'utf8');
    else text = String(data);

    let msg = null;
    try {
      msg = JSON.parse(text);
    } catch (_e) {
      this._sendError(client, 'Invalid JSON.');
      return;
    }
    this._handleClientMessage(client, msg);
  }

  start() {
    if (this.started) return;
    this.started = true;
    this.server = new ws.Server({ host: this.host, port: this.port }, (socket) => {
      const client = {
        socket,
        ready: !this.token,
        authed: !this.token,
        filter: this.defaultFilter,
        channels: null,
      };
      this.clients.add(client);

      const hello = {
        type: 'hello',
        peer: this.peer?.wallet?.publicKey ?? null,
        address: this.peer?.wallet?.address ?? null,
        entryChannel: this.sidechannel?.entryChannel ?? null,
        filter: this.defaultFilterRaw || '',
        requiresAuth: Boolean(this.token),
      };
      this._broadcastToClient(client, hello);

      socket.on('data', (data) => this._handleSocketData(client, data));
      const cleanup = () => this.clients.delete(client);
      socket.on('close', cleanup);
      socket.on('end', cleanup);
      socket.on('error', cleanup);
    });
  }

  stop() {
    if (!this.server) return;
    try {
      this.server.close();
    } catch (_e) {}
    this.server = null;
    this.started = false;
    this.clients.clear();
  }
}

export default ScBridge;
