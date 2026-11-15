// S2S legacy (v1) + v3 at the HTTP boundary of the real server: floor 1, audience
// 'rocketcyber', required headers bound by the v3 signature, boot checks, routing.
import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { createServer as createHttpServer } from 'node:http';
import { connect } from 'node:net';
import { RocketCyberMcpServer, S2S_AUDIENCE, S2S_FLOOR, REQUIRE_SIGNED_HEADERS } from '../server.js';
import { installNoRedirectFetch } from '../../utils/no-redirect-fetch.js';
import { signV1, signV3 } from './s2s-signers.js';

const SECRET = 'test-s2s-v3-http-secret-do-not-use-in-prod';
const HOST = '127.0.0.1';
const ENV_KEYS = ['CONDUIT_S2S_SECRET', 'ITSL_S2S_MIN_VERSION'];
const realFetch = globalThis.fetch;

type Entry = { level: string; msg: string; meta?: unknown };

const body = JSON.stringify({ jsonrpc: '2.0', method: 'tools/list', id: 1 });

function makeLogger(logs: Entry[]) {
  const rec = (level: string) => (msg: string, meta?: unknown) => { logs.push({ level, msg, meta }); };
  return { debug: rec('debug'), info: rec('info'), warn: rec('warn'), error: rec('error') };
}

let nextPort = 47610;

async function boot(opts: { minVersion?: string; secret?: string | null; gateway?: boolean } = {}) {
  for (const k of ENV_KEYS) delete process.env[k];
  if (opts.secret !== null) process.env.CONDUIT_S2S_SECRET = opts.secret ?? SECRET;
  if (opts.minVersion !== undefined) process.env.ITSL_S2S_MIN_VERSION = opts.minVersion;
  const port = nextPort++;
  const logs: Entry[] = [];
  const logger = makeLogger(logs);
  const envConfig = {
    rocketcyber: { apiKey: undefined, region: 'us' },
    server: { name: 'rocketcyber-mcp', version: 'test' },
    transport: { type: 'http' as const, port, host: HOST },
    logging: { level: 'info' as const, format: 'json' as const },
    auth: { mode: opts.gateway ? ('gateway' as const) : ('env' as const) },
  };
  const server = new RocketCyberMcpServer(
    { name: 'rocketcyber-mcp', version: 'test', rocketcyber: { apiKey: undefined, region: 'us' } },
    logger as never,
    envConfig,
  );
  await server.start();
  const post = (headers: Record<string, string>, b: string = body, path = '/mcp') =>
    realFetch(`http://${HOST}:${port}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', ...headers },
      body: b,
    });
  const v3 = (headers: Record<string, string> = {}, b: string = body) =>
    signV3(SECRET, { aud: S2S_AUDIENCE, method: 'POST', path: '/mcp', body: b, headers });
  return { server, port, logs, post, v3 };
}

let running: Array<{ server: RocketCyberMcpServer }> = [];
afterEach(async () => {
  for (const r of running) await r.server.stop();
  running = [];
  for (const k of ENV_KEYS) delete process.env[k];
});
async function start(opts?: Parameters<typeof boot>[0]) {
  const h = await boot(opts);
  running.push(h);
  return h;
}

describe('configuration pinned to the gateway', () => {
  it('audience is rocketcyber, floor is 1, required headers are the credential and region headers', () => {
    expect(S2S_AUDIENCE).toBe('rocketcyber');
    expect(S2S_FLOOR).toBe(1);
    expect(REQUIRE_SIGNED_HEADERS).toEqual(['x-rocketcyber-api-key', 'x-rocketcyber-region']);
  });
});

describe('legacy (v1) at the floor', () => {
  it('accepts a v1 header (default minimum 1)', async () => {
    const h = await start();
    const r = await h.post({ 'x-gateway-s2s': signV1(SECRET) });
    expect(r.status).toBe(200);
    expect((await r.json()).result.tools.length).toBeGreaterThan(0);
  });

  it('refuses a missing header, a wrong-secret v1 header and a v2-shaped header', async () => {
    const h = await start();
    expect((await h.post({})).status).toBe(401);
    expect((await h.post({ 'x-gateway-s2s': signV1('another-secret-another-secret-123456') })).status).toBe(401);
    expect((await h.post({ 'x-gateway-s2s': `t=${Math.floor(Date.now() / 1000)},v2=${'0'.repeat(64)}` })).status).toBe(401);
  });
});

describe('v3', () => {
  it('accepts a v3 header (report mode, minimum 1) and refuses its replay', async () => {
    const h = await start();
    const header = h.v3();
    expect((await h.post({ 'x-gateway-s2s': header })).status).toBe(200);
    expect((await h.post({ 'x-gateway-s2s': header })).status).toBe(401);
  });

  it('refuses a v3 header for another audience or another body', async () => {
    const h = await start();
    const wrongAud = signV3(SECRET, { aud: 'cipp', method: 'POST', path: '/mcp', body });
    expect((await h.post({ 'x-gateway-s2s': wrongAud })).status).toBe(401);
    expect((await h.post({ 'x-gateway-s2s': h.v3({}, '{"other":1}') })).status).toBe(401);
  });

  for (const name of ['x-rocketcyber-api-key', 'x-rocketcyber-region']) {
    it(`refuses ${name} when present but unsigned, even in report mode`, async () => {
      const h = await start({ minVersion: '1', gateway: true });
      const r = await h.post({ 'x-gateway-s2s': h.v3({}), [name]: 'attacker-supplied' });
      expect(r.status).toBe(401);
    });
  }

  it('honours the required headers when they are signed (gateway mode)', async () => {
    const h = await start({ gateway: true });
    const signed = { 'x-rocketcyber-api-key': 'test-key-not-real', 'x-rocketcyber-region': 'eu' };
    const r = await h.post({ 'x-gateway-s2s': h.v3(signed), ...signed });
    expect(r.status).toBe(200);
    // and gateway mode still demands the key itself
    const noKey = await h.post({ 'x-gateway-s2s': h.v3({}) });
    expect(noKey.status).toBe(401);
    expect((await noKey.json()).error).toBe('Missing credentials');
  });
});

describe('minimum version 3', () => {
  it('refuses legacy, accepts v3, and logs the header rule as enforced', async () => {
    const h = await start({ minVersion: '3' });
    expect((await h.post({ 'x-gateway-s2s': signV1(SECRET) })).status).toBe(401);
    expect((await h.post({ 'x-gateway-s2s': h.v3() })).status).toBe(200);
    expect(h.logs.some((l) => l.level === 'info' && l.msg.includes('effective minimum version 3') && l.msg.includes('enforced'))).toBe(true);
  });

  it('a typo in ITSL_S2S_MIN_VERSION can only tighten (treated as 3)', async () => {
    const h = await start({ minVersion: 'banana' });
    expect((await h.post({ 'x-gateway-s2s': signV1(SECRET) })).status).toBe(401);
  });
});

describe('start-up', () => {
  it('logs the effective minimum version and report mode once, without any secret', async () => {
    const h = await start();
    const lines = h.logs.filter((l) => l.msg.startsWith('S2S verification:'));
    expect(lines).toHaveLength(1);
    expect(lines[0].level).toBe('info');
    expect(lines[0].msg).toContain('effective minimum version 1');
    expect(lines[0].msg).toContain('report mode');
    expect(JSON.stringify(h.logs)).not.toContain(SECRET);
  });

  it('refuses to start in HTTP mode without a secret, or with a short one', async () => {
    await expect(boot({ secret: null })).rejects.toThrow(/CONDUIT_S2S_SECRET/);
    await expect(boot({ secret: 'x'.repeat(31) })).rejects.toThrow(/at least 32/);
  });
});

describe('routing and robustness', () => {
  it('answers 404 on unknown paths before auth, and /health without auth', async () => {
    const h = await start();
    expect((await h.post({}, body, '/other')).status).toBe(404);
    expect((await h.post({}, body, '/')).status).toBe(404);
    expect((await h.post({}, body, '/healthz')).status).toBe(404);
    const r = await realFetch(`http://${HOST}:${h.port}/health`);
    expect(r.status).toBe(200);
  });

  it('an aborted upload does not crash the server', async () => {
    const h = await start();
    await new Promise<void>((resolve) => {
      const s = connect(h.port, HOST, () => {
        s.write(`POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nX-Gateway-S2S: ${signV1(SECRET)}\r\nContent-Length: 1000\r\n\r\n{"jsonrpc"`);
        setTimeout(() => { s.destroy(); resolve(); }, 50);
      });
      s.on('error', () => resolve());
    });
    await new Promise((r) => setTimeout(r, 100));
    expect((await realFetch(`http://${HOST}:${h.port}/health`)).status).toBe(200);
  });

  it('non-POST is 405 only after S2S verification', async () => {
    const h = await start();
    const unauth = await realFetch(`http://${HOST}:${h.port}/mcp`);
    expect(unauth.status).toBe(401);
    const authed = await realFetch(`http://${HOST}:${h.port}/mcp`, { headers: { 'x-gateway-s2s': signV1(SECRET) } });
    expect(authed.status).toBe(405);
  });
});

describe('vendor redirects fail closed', () => {
  beforeAll(() => installNoRedirectFetch());

  it('a 3xx from the upstream rejects instead of being followed, and the wrapper installs once', async () => {
    let targetHit = false;
    const target = createHttpServer((_req, res) => { targetHit = true; res.end('secret-leak'); });
    await new Promise<void>((r) => target.listen(0, HOST, () => r()));
    const targetPort = (target.address() as { port: number }).port;
    const redirector = createHttpServer((_req, res) => {
      res.writeHead(302, { Location: `http://${HOST}:${targetPort}/` });
      res.end();
    });
    await new Promise<void>((r) => redirector.listen(0, HOST, () => r()));
    const redirPort = (redirector.address() as { port: number }).port;
    const before = globalThis.fetch;
    installNoRedirectFetch();
    expect(globalThis.fetch).toBe(before);
    // Same call shape the SDK uses: fetch(url, { method, headers, body }).
    await expect(
      globalThis.fetch(`http://${HOST}:${redirPort}/`, { method: 'GET', headers: { 'X-API-Key': 'k' } }),
    ).rejects.toThrow();
    expect(targetHit).toBe(false);
    // An explicit redirect: 'follow' from a caller is overridden too.
    await expect(
      globalThis.fetch(`http://${HOST}:${redirPort}/`, { redirect: 'follow' }),
    ).rejects.toThrow();
    expect(targetHit).toBe(false);
    await new Promise<void>((r) => target.close(() => r()));
    await new Promise<void>((r) => redirector.close(() => r()));
  });
});
