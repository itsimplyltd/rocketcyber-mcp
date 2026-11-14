import { createServer, IncomingMessage, ServerResponse, Server as HttpServer } from 'node:http';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListResourcesRequestSchema,
  ListToolsRequestSchema,
  McpError,
  ReadResourceRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

import { RocketCyberService } from '../services/rocketcyber.service.js';
import { Logger } from '../utils/logger.js';
import { McpServerConfig } from '../types/mcp.js';
import { EnvironmentConfig, parseCredentialsFromHeaders, GatewayCredentials } from '../utils/config.js';
import { RocketCyberResourceHandler } from '../handlers/resource.handler.js';
import { RocketCyberToolHandler } from '../handlers/tool.handler.js';
import { verifyS2sHeader } from './s2s-verify.js';
import {
  NonceCache,
  ReportRateLimiter,
  assertRequireSignedHeaders,
  effectiveMinVersion,
  handleGatewayRequest,
} from '../itsl/s2s-v3.js';

// S2S v3 (phase A). The gateway's audience for this vendor: cred-router signs
// with aud = 'rocketcyber' (finishSignedProxyRequest default: aud = vendor).
export const S2S_AUDIENCE = 'rocketcyber';
// The legacy verifier (s2s-verify.ts) is v1 only and nothing can tighten it, so
// v1 is what is enforced today and the floor can only be 1.
export const S2S_FLOOR = 1;
const MIN_S2S_SECRET_LENGTH = 32;
// Credential and region headers this backend reads in gateway mode. cred-router
// does not set either today (the key is baked into this container), and its
// client-header allow-list strips them if a caller sends them. If either ever
// arrives on a v3 request it must be covered by the signature.
export const REQUIRE_SIGNED_HEADERS = ['x-rocketcyber-api-key', 'x-rocketcyber-region'];
assertRequireSignedHeaders(REQUIRE_SIGNED_HEADERS);

// One per process: v3 nonces are single-use inside the skew window.
const nonceCache = new NonceCache();
const reportLimiter = new ReportRateLimiter();
const failureLimiter = new ReportRateLimiter();

export class RocketCyberMcpServer {
  private server: Server;
  private config: McpServerConfig;
  private rcService: RocketCyberService;
  private resourceHandler: RocketCyberResourceHandler;
  private toolHandler: RocketCyberToolHandler;
  private logger: Logger;
  private envConfig: EnvironmentConfig | undefined;
  private httpServer?: HttpServer;

  constructor(config: McpServerConfig, logger: Logger, envConfig?: EnvironmentConfig) {
    this.logger = logger;
    this.config = config;
    this.envConfig = envConfig;

    this.rcService = new RocketCyberService(config, logger);
    this.resourceHandler = new RocketCyberResourceHandler(this.rcService, logger);
    this.toolHandler = new RocketCyberToolHandler(this.rcService, logger);

    // Create default server (used for stdio mode)
    this.server = this.createFreshServer();
  }

  /**
   * Create a fresh MCP Server with all handlers registered.
   * Called per-request in HTTP mode so each request gets a clean server.
   *
   * In gateway mode, per-request handlers are passed so each request is fully
   * isolated — no shared mutable state between concurrent requests.
   */
  private createFreshServer(
    perRequestToolHandler?: RocketCyberToolHandler,
    perRequestResourceHandler?: RocketCyberResourceHandler,
  ): Server {
    const server = new Server(
      { name: this.config.name, version: this.config.version },
      {
        capabilities: {
          resources: { subscribe: false, listChanged: true },
          tools: { listChanged: true }
        },
        instructions: this.getServerInstructions()
      }
    );

    server.onerror = (error) => this.logger.error('MCP Server error:', error);
    server.oninitialized = () => this.logger.info('MCP Server initialized and ready');

    this.setupHandlers(
      server,
      perRequestToolHandler ?? this.toolHandler,
      perRequestResourceHandler ?? this.resourceHandler,
    );
    return server;
  }

  /**
   * Build per-request service + handlers from gateway credentials.
   * Returns fully isolated instances that won't be affected by concurrent requests.
   */
  private buildPerRequestHandlers(credentials: GatewayCredentials): {
    toolHandler: RocketCyberToolHandler;
    resourceHandler: RocketCyberResourceHandler;
  } {
    const requestConfig: McpServerConfig = {
      ...this.config,
      rocketcyber: {
        apiKey: credentials.apiKey,
        region: credentials.region ?? this.config.rocketcyber?.region,
      },
    };
    const service = new RocketCyberService(requestConfig, this.logger);
    return {
      resourceHandler: new RocketCyberResourceHandler(service, this.logger),
      toolHandler: new RocketCyberToolHandler(service, this.logger),
    };
  }

  /**
   * Build a fresh, fully-configured MCP `Server` for a single request.
   *
   * This is the transport-agnostic seam reused by the Cloudflare Workers
   * entrypoint (`worker.ts`): the Worker owns its own Web Standard transport
   * and only needs a ready-to-connect `Server`. When `credentials` are
   * provided (gateway mode), per-request isolated handlers are built from them;
   * otherwise the instance's env-configured handlers are used.
   */
  public createServerForRequest(credentials?: GatewayCredentials): Server {
    if (credentials?.apiKey) {
      const { toolHandler, resourceHandler } =
        this.buildPerRequestHandlers(credentials);
      return this.createFreshServer(toolHandler, resourceHandler);
    }
    return this.createFreshServer();
  }

  private setupHandlers(
    server: Server,
    toolHandler: RocketCyberToolHandler,
    resourceHandler: RocketCyberResourceHandler,
  ): void {
    this.logger.info('Setting up MCP request handlers...');

    server.setRequestHandler(ListResourcesRequestSchema, async () => {
      try {
        const resources = await resourceHandler.listResources();
        return { resources };
      } catch (error) {
        this.logger.error('Failed to list resources:', error);
        throw new McpError(ErrorCode.InternalError, `Failed to list resources: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    });

    server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
      try {
        const content = await resourceHandler.readResource(request.params.uri);
        return { contents: [content] };
      } catch (error) {
        this.logger.error(`Failed to read resource ${request.params.uri}:`, error);
        throw new McpError(ErrorCode.InternalError, `Failed to read resource: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    });

    server.setRequestHandler(ListToolsRequestSchema, async () => {
      try {
        const tools = await toolHandler.listTools();
        return { tools };
      } catch (error) {
        this.logger.error('Failed to list tools:', error);
        throw new McpError(ErrorCode.InternalError, `Failed to list tools: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    });

    server.setRequestHandler(CallToolRequestSchema, async (request) => {
      try {
        const result = await toolHandler.callTool(request.params.name, request.params.arguments || {});
        return { content: result.content, isError: result.isError };
      } catch (error) {
        this.logger.error(`Failed to call tool ${request.params.name}:`, error);
        throw new McpError(ErrorCode.InternalError, `Failed to call tool: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    });

    this.logger.info('MCP request handlers set up successfully');
  }

  async start(): Promise<void> {
    const transportType = this.envConfig?.transport?.type || 'stdio';
    this.logger.info(`Starting RocketCyber MCP Server with ${transportType} transport...`);

    if (transportType === 'http') {
      await this.startHttpTransport();
    } else {
      await this.startStdioTransport();
    }
  }

  private async startStdioTransport(): Promise<void> {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    this.logger.info('RocketCyber MCP Server connected to stdio transport');
  }

  /**
   * Start with HTTP Streamable transport.
   * Stateless: each request gets a fresh Server + Transport so multiple
   * clients (via the gateway) never hit "Server already initialized".
   */
  private async startHttpTransport(): Promise<void> {
    const port = this.envConfig?.transport?.port || 8080;
    const host = this.envConfig?.transport?.host || '0.0.0.0';
    const isGatewayMode = this.envConfig?.auth?.mode === 'gateway';

    // Boot check: HTTP mode never starts without a real S2S secret. An empty or
    // short secret used to mean "S2S disabled" (every /mcp request served
    // unauthenticated); that is now a deployment fault. The value is never logged.
    const s2sSecret = process.env.CONDUIT_S2S_SECRET || '';
    if (s2sSecret.length < MIN_S2S_SECRET_LENGTH) {
      throw new Error(
        `Refusing to start HTTP server: CONDUIT_S2S_SECRET must be set to at least ${MIN_S2S_SECRET_LENGTH} characters ` +
        '(for example the output of `openssl rand -hex 32`).'
      );
    }

    // Operator switch for the S2S v3 rollout. Raw: anything that is not an
    // integer 1..3 is treated as 3 by the verifier (a typo can only tighten).
    const minVersion = Number(process.env.ITSL_S2S_MIN_VERSION ?? String(S2S_FLOOR));
    const effectiveMin = effectiveMinVersion(S2S_FLOOR, minVersion);
    // The blanket header rule is enforced only at effective minimum 3; below
    // that the verifier runs it in report mode (requireSignedHeaders still binds).
    this.logger.info(
      `S2S verification: effective minimum version ${effectiveMin}; ` +
      `v3 header rule ${effectiveMin === 3 ? 'enforced' : 'in report mode'}`,
      { s2sEffectiveMinVersion: effectiveMin, s2sHeaderRule: effectiveMin === 3 ? 'enforced' : 'report' }
    );

    this.httpServer = createServer(async (req: IncomingMessage, res: ServerResponse) => {
      // Raw target, not a parsed URL: the signed path is exactly what was sent.
      const rawTarget = req.url ?? '/';
      const queryAt = rawTarget.indexOf('?');
      const pathname = queryAt === -1 ? rawTarget : rawTarget.slice(0, queryAt);

      // Health endpoint - no auth required, no vendor call, no credentials read.
      if (pathname === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          status: 'ok',
          transport: 'http',
          authMode: isGatewayMode ? 'gateway' : 'env',
          timestamp: new Date().toISOString()
        }));
        return;
      }

      // 404 for everything except the MCP endpoint, before any auth.
      if (pathname !== '/mcp') {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Not found', endpoints: ['/mcp', '/health'] }));
        return;
      }

      // MCP endpoint. The shared wrapper runs the S2S check FIRST (before the
      // method check or credential extraction), reads the body once, and never
      // rejects: an aborted upload or a throwing handler ends that request, not
      // the process. There is no unauthenticated mode (allowUnauthenticated is
      // deliberately never set).
      await handleGatewayRequest(
        req,
        res,
        {
          secret: s2sSecret,
          aud: S2S_AUDIENCE,
          floor: S2S_FLOOR,
          minVersion,
          verifyLegacy: (headerValue) => (verifyS2sHeader(headerValue, s2sSecret) ? 1 : 0),
          nonceCache,
          reportLimiter,
          failureLimiter,
          logger: this.logger,
          requireSignedHeaders: REQUIRE_SIGNED_HEADERS,
        },
        async ({ parsedBody }) => {
          // Only POST is supported in stateless mode
          if (req.method !== 'POST') {
            res.writeHead(405, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              jsonrpc: '2.0',
              error: { code: -32000, message: 'Method not allowed' },
              id: null,
            }));
            return;
          }

          // In gateway mode, build per-request service + handlers from the
          // injected credential headers. Each request gets its own isolated
          // RocketCyberService so concurrent requests for different tenants
          // never interfere with each other.
          let perRequestToolHandler: RocketCyberToolHandler | undefined;
          let perRequestResourceHandler: RocketCyberResourceHandler | undefined;
          if (isGatewayMode) {
            const credentials = this.extractGatewayCredentials(req);
            if (!credentials.apiKey) {
              this.logger.warn('Gateway mode: Missing required API key in headers');
              res.writeHead(401, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({
                error: 'Missing credentials',
                message: 'Gateway mode requires X-RocketCyber-API-Key header',
                required: ['X-RocketCyber-API-Key']
              }));
              return;
            }
            const handlers = this.buildPerRequestHandlers(credentials);
            perRequestToolHandler = handlers.toolHandler;
            perRequestResourceHandler = handlers.resourceHandler;
          }

          // Stateless: create fresh server + transport for each request
          const server = this.createFreshServer(perRequestToolHandler, perRequestResourceHandler);
          const transport = new StreamableHTTPServerTransport({
            enableJsonResponse: true,
          });

          res.on('close', () => {
            transport.close();
            server.close();
          });

          try {
            await server.connect(transport as unknown as Transport);
            // The wrapper already consumed the body, so hand the transport the parsed JSON.
            await transport.handleRequest(req, res, parsedBody);
          } catch (err) {
            this.logger.error('MCP transport error:', err);
            if (!res.headersSent) {
              res.writeHead(500, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({
                jsonrpc: '2.0',
                error: { code: -32603, message: 'Internal error' },
                id: null,
              }));
            }
          }
        },
      );
    });

    await new Promise<void>((resolve) => {
      this.httpServer!.listen(port, host, () => {
        this.logger.info(`RocketCyber MCP Server listening on http://${host}:${port}/mcp`);
        this.logger.info(`Health check available at http://${host}:${port}/health`);
        this.logger.info(`Authentication mode: ${isGatewayMode ? 'gateway (header-based)' : 'env (environment variables)'}`);
        resolve();
      });
    });
  }

  private extractGatewayCredentials(req: IncomingMessage): GatewayCredentials {
    const headers = req.headers as Record<string, string | string[] | undefined>;
    return parseCredentialsFromHeaders(headers);
  }

  async stop(): Promise<void> {
    this.logger.info('Stopping RocketCyber MCP Server...');
    if (this.httpServer) {
      await new Promise<void>((resolve, reject) => {
        this.httpServer!.close((err) => err ? reject(err) : resolve());
      });
    }
    await this.server.close();
    this.logger.info('RocketCyber MCP Server stopped');
  }

  private getServerInstructions(): string {
    return `# RocketCyber MCP Server

This server provides read-only access to RocketCyber Managed SOC data through the Model Context Protocol.

## Available Resources:
- **rocketcyber://account** - Account information
- **rocketcyber://incidents** - Security incidents
- **rocketcyber://agents** - Monitored agents/endpoints

## Available Tools (10 total):
- Account: get account info
- Agents: list monitored agents
- Incidents: list security incidents
- Events: list events, get event summary
- Firewalls: list firewall devices
- Apps: list managed apps
- Defender: get Windows Defender status
- Office: get Office 365 status
- Utility: test connection

## Authentication:
- ROCKETCYBER_API_KEY (required) - Your RocketCyber API key
- ROCKETCYBER_REGION (optional) - API region: us (default) or eu`;
  }
}
