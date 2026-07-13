/**
 * OpenClaw OVID-ME Plugin — Mandate evaluation tools
 */

import {
  evaluateMandate,
  MandateEngine,
  AuditDatabase,
  startDashboard,
  stopDashboard,
  resolveConfig,
  AuthZenServer,
  type OvidConfig,
  type EvaluateRequest,
} from '@clawdreyhepburn/ovid-me';

export const id = 'openclaw-ovid-me';
export const name = 'OVID-ME';

interface PluginConfig {
  mandateMode?: 'enforce' | 'dry-run' | 'shadow';
  auditLog?: string;
  auditDb?: string;
  dashboardPort?: number;
  authzenPort?: number;
  authzenEnabled?: boolean;
  subsetProof?: 'required' | 'advisory' | 'off';
  enforcementFailure?: 'closed' | 'open';
}

interface OpenClawPluginApi {
  pluginConfig: any;
  logger: {
    info(msg: string, ...args: any[]): void;
    warn(msg: string, ...args: any[]): void;
    error(msg: string, ...args: any[]): void;
  };
  registerService(service: { id: string; start(): Promise<void> | void; stop(): Promise<void> | void }): void;
  registerTool(
    tool: {
      name: string;
      label?: string;
      description: string;
      parameters: Record<string, any>;
      execute(toolCallId: string, params: any): Promise<any>;
    },
    opts?: { optional?: boolean },
  ): void;
  registerCli?(fn: (ctx: { program: any }) => void, opts?: { commands: string[] }): void;
  on?(hookName: string, handler: (...args: any[]) => any, opts?: { name?: string; description?: string }): void;
}

let engine: MandateEngine | null = null;
let auditDb: AuditDatabase | null = null;
let dashboardRunning = false;
let authzenServer: AuthZenServer | null = null;

// Cache: sessionKey → parsed OVID mandate for sub-agents
interface SessionMandate {
  agentJti: string;
  policySet: string;
  jwt: string;
  /** Whether the child's mandate was formally proven as a subset of the parent's */
  proven: boolean;
  /** Method used for subset proof */
  proofMethod: string;
}
const sessionMandates = new Map<string, SessionMandate | null>();

function extractOvidFromTask(task: string): SessionMandate | null {
  const match = task.match(/\[OVID_IDENTITY\][\s\S]*?Token \(JWT\): ([^\n]+)[\s\S]*?\[\/OVID_IDENTITY\]/);
  if (!match) return null;

  // Also extract the issuer public key for verification
  const pubMatch = task.match(/Issuer public key: ([^\n]+)/);

  try {
    const jwt = match[1].trim();
    const payload = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());
    const detail = payload.authorization_details?.[0];
    if (!detail?.policySet) return null;
    return {
      agentJti: payload.jti ?? payload.sub ?? 'unknown',
      policySet: detail.policySet,
      jwt,
      proven: false,
      proofMethod: 'none',
    };
  } catch {
    return null;
  }
}


export default function register(api: OpenClawPluginApi) {
  const config: PluginConfig = api.pluginConfig ?? {};
  const logger = api.logger;

  const mandateMode = config.mandateMode ?? 'dry-run';
  const dashboardPort = config.dashboardPort ?? 19831;
  const authzenPort = config.authzenPort ?? 19832;
  const authzenEnabled = config.authzenEnabled ?? true;
  const auditDbPath = config.auditDb ?? `${process.env.HOME}/.ovid/audit.db`;

  // --- Service ---
  api.registerService({
    id: 'ovid-me',
    async start() {
      // PolicySource: returns the effective Cedar policy for a given principal.
      // The root issuer has a broad permit-all mandate; child mandates must be
      // strict subsets of this. We read the root issuer name from identity.json.
      let rootIssuerName = 'root';
      try {
        const identityPath = `${process.env.HOME}/.ovid/keys/identity.json`;
        const fs = await import('node:fs');
        if (fs.existsSync(identityPath)) {
          const identity = JSON.parse(fs.readFileSync(identityPath, 'utf-8'));
          rootIssuerName = identity.rootIssuer ?? 'root';
        }
      } catch { /* ignore */ }

      const policySource = {
        async getEffectivePolicy(principal: string): Promise<string | null> {
          // The root issuer has a genuine allow-all policy — it is the top of
          // the authority chain. Child mandates (which use an unconstrained
          // `principal`) must be a provable subset of THIS. Scoping the parent
          // to `principal == Ovid::Agent::"clawdrey"` was a bug: it made the
          // parent NARROWER than the child on the principal axis, so the SMT
          // prover correctly returned not-a-subset (counterexample: any other
          // principal doing `summarize`). True allow-all is the correct root.
          if (principal === rootIssuerName) {
            return `permit(principal, action, resource);`;
          }
          // For non-root principals, look up their cached mandate
          for (const [, m] of sessionMandates) {
            if (m && m.agentJti === principal) return m.policySet;
          }
          return null;
        },
      };

      const ovidConfig: Partial<OvidConfig> = {
        mandateMode,
        auditLog: config.auditLog ?? null,
        auditDb: config.auditDb ?? null,
        dashboardPort,
        subsetProof: config.subsetProof ?? 'off',
        // Reflexive fallback: if the SMT prover binary is ever absent/erroring,
        // still prove exact/normalized subsets (method='structural-normalized')
        // instead of silently returning method='none'. Defaults to 'off' in the
        // library, which masks prover failures as unproven.
        structuralFallback: (config as any).structuralFallback ?? 'normalized',
        enforcementFailure: config.enforcementFailure ?? 'closed',
        policySource,
      };

      engine = new MandateEngine(ovidConfig);

      auditDb = new AuditDatabase(auditDbPath);
      try {
        await startDashboard({ dbPath: auditDbPath, port: dashboardPort });
        dashboardRunning = true;
        logger.info(`OVID-ME forensics dashboard at http://localhost:${dashboardPort}`);
      } catch (err: any) {
        logger.warn(`OVID-ME dashboard failed to start: ${err.message}`);
      }

      if (authzenEnabled) {
        try {
          authzenServer = new AuthZenServer({ port: authzenPort, ovidConfig });
          await authzenServer.start();
          logger.info(`OVID-ME AuthZEN PDP at http://127.0.0.1:${authzenPort}`);
        } catch (err: any) {
          logger.warn(`OVID-ME AuthZEN server failed to start: ${err.message}`);
          authzenServer = null;
        }
      }

      logger.info(`OVID-ME mandate evaluation active (mode: ${mandateMode})`);
    },
    async stop() {
      if (dashboardRunning) {
        await stopDashboard();
        dashboardRunning = false;
      }
      if (authzenServer) {
        await authzenServer.stop();
        authzenServer = null;
      }
    },
  });

  // --- Hooks: mandate evaluation + audit logging ---
  if (api.on) {
    // Record issuances when sessions_spawn completes with an OVID token
    api.on("after_tool_call", async (event: any, ctx: any) => {
      if (!auditDb) return;
      const toolName: string = event.toolName ?? "";
      const params: Record<string, unknown> = event.params ?? {};

      logger.info(`[OVID-ME] after_tool_call fired: tool=${toolName}`);

      if (toolName === "sessions_spawn") {
        logger.info(`[OVID-ME] sessions_spawn after_tool_call — checking for OVID token`);
        const task = (params.task as string) ?? "";
        logger.info(`[OVID-ME] Task length=${task.length}, has OVID_IDENTITY=${task.includes('[OVID_IDENTITY]')}`);
        const ovidMandate = extractOvidFromTask(task);
        logger.info(`[OVID-ME] extractOvidFromTask returned: ${ovidMandate ? ovidMandate.agentJti : 'null'}`);
        if (ovidMandate) {
          // event.result is a tool result envelope: { content: [{ type: 'text', text: '<json>' }] }
          // We need to unwrap the inner JSON to find childSessionKey.
          let childKey = '';
          try {
            const resultEnvelope = (typeof event.result === 'string' ? JSON.parse(event.result) : event.result) as any;
            // Try direct access first
            childKey = resultEnvelope?.childSessionKey ?? '';
            // If not found, unwrap from content[0].text
            if (!childKey && Array.isArray(resultEnvelope?.content)) {
              const textContent = resultEnvelope.content.find((c: any) => c.type === 'text');
              if (textContent?.text) {
                const inner = JSON.parse(textContent.text);
                childKey = inner?.childSessionKey ?? '';
              }
            }
          } catch { /* ignore parse errors */ }
          logger.info(`[OVID-ME] childKey=${childKey || '(empty)'}`);
          // Also try to get it from the event context directly
          if (!childKey) childKey = (event as any).childSessionKey ?? '';
          if (childKey) {
            // Run subset proof: is the child's mandate a subset of the parent's?
            if (engine) {
              try {
                const payload = JSON.parse(Buffer.from(ovidMandate.jwt.split('.')[1], 'base64url').toString());
                const parentIss = payload.iss ?? 'root';
                const proofResult = await engine.verifySubset(
                  { type: 'agent_mandate', rarFormat: 'cedar', policySet: ovidMandate.policySet },
                  parentIss,
                );
                ovidMandate.proven = proofResult.proven;
                ovidMandate.proofMethod = proofResult.method ?? 'none';
                if (proofResult.proven) {
                  logger.info(`[OVID-ME] Subset PROVEN for ${ovidMandate.agentJti} (method=${ovidMandate.proofMethod})`);
                } else {
                  logger.warn(`[OVID-ME] Subset NOT proven for ${ovidMandate.agentJti}: ${proofResult.reason ?? 'unknown'}`);
                }
              } catch (err: any) {
                logger.warn(`[OVID-ME] Subset proof error for ${ovidMandate.agentJti}: ${err.message}`);
                ovidMandate.proven = false;
              }
            }
            sessionMandates.set(childKey, ovidMandate);
            logger.info(`[OVID-ME] Cached mandate for ${ovidMandate.agentJti} -> session ${childKey.slice(-12)} (proven=${ovidMandate.proven}, method=${ovidMandate.proofMethod})`);
          }

          try {
            const payload = JSON.parse(Buffer.from(ovidMandate.jwt.split('.')[1], 'base64url').toString());
            const detail = payload.authorization_details?.[0];
            // parent_chain is now ChainLink[] (objects with .sub), not string[].
            // Normalize to subject strings so `depth = parent_chain.length` is
            // correct (3 for a grandchild) and the chains edge is parent->child.
            const rawChain =
              (detail?.parentChain as any[] | undefined) ??
              (detail?.parent_chain as any[] | undefined) ??
              (payload.parent_chain as any[] | undefined) ??
              [];
            const chainSubs: string[] = Array.isArray(rawChain)
              ? rawChain.map((l: any) => (typeof l === 'string' ? l : (l?.sub ?? '')))
              : [];
            auditDb.recordIssuance({
              jti: ovidMandate.agentJti,
              iss: payload.iss ?? 'root',
              mandate_summary: detail?.policySet?.slice(0, 100) ?? 'none',
              parent_chain: chainSubs,
              iat: payload.iat ?? Math.floor(Date.now() / 1000),
              exp: payload.exp ?? 0,
              raw_jwt: ovidMandate.jwt,
            });
            logger.info(`[OVID-ME] Recorded issuance: ${ovidMandate.agentJti}`);
          } catch (err: any) {
            logger.warn(`[OVID-ME] Failed to record issuance: ${err.message}`);
          }
        }
      }
    }, {
      name: "ovid-me.issuance-recorder",
      description: "Record OVID token issuances to audit database",
    });

    // Evaluate every tool call against the session's OVID mandate
    api.on("before_tool_call", async (event: any, ctx: any) => {
      if (!auditDb) return {};
      const sessionKey: string = ctx?.sessionKey ?? "";
      const toolName: string = event.toolName ?? event.tool ?? event.name ?? "";
      const params: Record<string, unknown> = event.params ?? {};

      logger.info(`[OVID-ME] before_tool_call: tool=${toolName} session=${sessionKey.slice(-20)} isSubagent=${sessionKey.includes('subagent:')}`);

      // Skip if this isn't a sub-agent session (no "subagent:" prefix)
      if (!sessionKey.includes("subagent:")) return {};

      // Look up or cache the session's OVID mandate
      if (!sessionMandates.has(sessionKey)) {
        // We don't have the task text here, so mark as unknown for now.
        // It gets populated on first tool call after we see the session.
        sessionMandates.set(sessionKey, null);
      }

      const mandate = sessionMandates.get(sessionKey);
      if (!mandate) return {}; // No mandate found yet

      // ── Map tool call to Cedar action + typed resource ──
      // The action is a verb from the Ovid schema.
      // The resource carries typed context (path, command, url, etc.)
      let action = 'call_tool';
      let resourceType = 'Tool';
      let resourceAttrs: Record<string, string> = { name: toolName };

      switch (toolName) {
        case 'read':
          action = 'read';
          resourceType = 'File';
          resourceAttrs = { path: String(params.path ?? '') };
          break;
        case 'write':
          action = 'write';
          resourceType = 'File';
          resourceAttrs = { path: String(params.path ?? '') };
          break;
        case 'edit':
          action = 'edit';
          resourceType = 'File';
          resourceAttrs = { path: String(params.path ?? '') };
          break;
        case 'exec': {
          action = 'exec';
          resourceType = 'Shell';
          const cmd = String(params.command ?? '');
          resourceAttrs = { command: cmd.split(/\s+/)[0] || cmd, args: cmd };
          break;
        }
        case 'process':
          action = 'exec';
          resourceType = 'Shell';
          resourceAttrs = { command: 'process', args: String(params.action ?? '') };
          break;
        case 'web_fetch': {
          action = 'fetch';
          resourceType = 'WebEndpoint';
          const fetchUrl = String(params.url ?? '');
          try { resourceAttrs = { url: fetchUrl, hostname: new URL(fetchUrl).hostname }; }
          catch { resourceAttrs = { url: fetchUrl }; }
          break;
        }
        case 'web_search':
          action = 'search';
          resourceType = 'WebEndpoint';
          resourceAttrs = { url: String(params.query ?? '') };
          break;
        case 'browser':
          action = 'browse';
          resourceType = 'WebEndpoint';
          resourceAttrs = { url: String(params.url ?? '') };
          break;
        case 'message':
          action = 'send';
          resourceType = 'Channel';
          resourceAttrs = { provider: String(params.channel ?? 'unknown'), target: String(params.target ?? '') };
          break;
        case 'sessions_spawn':
          action = 'delegate';
          resourceType = 'Session';
          resourceAttrs = { key: String(params.label ?? '') };
          break;
        case 'memory_search':
        case 'memory_get':
          action = 'recall';
          resourceType = 'Memory';
          resourceAttrs = { path: String(params.path ?? params.query ?? '') };
          break;
        case 'tts':
          action = 'call_tool';
          resourceType = 'Tool';
          resourceAttrs = { name: 'tts' };
          break;
        case 'image':
        case 'pdf':
          action = 'read';
          resourceType = 'File';
          resourceAttrs = { path: String(params.image ?? params.pdf ?? '') };
          break;
        default:
          break;
      }

      const resourceId = `Ovid::${resourceType}::"${toolName}"`;

      // Evaluate against Cedar mandate
      let decision: 'allow' | 'deny' = 'allow';
      let matchedPolicy: string | null = null;
      try {
        const result = evaluateMandate(mandate.policySet, {
          action,
          resource: toolName,
          ...(Object.keys(resourceAttrs).length > 0 ? { context: { resourceType, ...resourceAttrs } } : {}),
        });
        decision = result.decision === 'allow' ? 'allow' : 'deny';
        matchedPolicy = result.matchedPolicy ?? null;
      } catch (err: any) {
        logger.warn(`[OVID-ME] Mandate eval failed for ${mandate.agentJti}: ${err.message}`);
        decision = mandateMode === 'enforce' ? 'deny' : 'allow';
      }

      // Record decision with proven/unproven distinction
      const qualifiedDecision = decision === 'allow'
        ? (mandate.proven ? 'allow-proven' : 'allow-unproven')
        : decision;

      auditDb.recordDecision(
        mandate.agentJti,
        action,
        `${resourceType}:${toolName}`,
        qualifiedDecision,
        matchedPolicy ? [matchedPolicy] : [],
      );

      if (decision === 'deny') {
        logger.info(`[OVID-ME] ${mandateMode === 'enforce' ? 'DENIED' : 'WOULD DENY'}: ${toolName} for ${mandate.agentJti}`);
        if (mandateMode === 'enforce') {
          return { block: true, blockReason: `OVID mandate denied: ${toolName} not authorized for ${mandate.agentJti}` };
        }
      }

      return {};
    }, {
      name: "ovid-me.mandate-evaluator",
      description: "Evaluate sub-agent tool calls against OVID mandates",
    });

    logger.info("Registered OVID-ME hooks: mandate evaluation + audit logging");
  }

  // --- Tool: ovid_evaluate ---
  api.registerTool(
    {
      name: 'ovid_evaluate',
      label: 'OVID Evaluate',
      description: 'Evaluate a tool call against a Cedar mandate. Returns allow/deny with matched policy and reason.',
      parameters: {
        type: 'object',
        required: ['mandate', 'action', 'resource'],
        properties: {
          mandate: { type: 'string', description: 'Cedar policy text' },
          action: { type: 'string', description: 'Action to evaluate (e.g., "call_tool")' },
          resource: { type: 'string', description: 'Resource path (e.g., "/api/users")' },
        },
      },
      async execute(_toolCallId: string, params: { mandate: string; action: string; resource: string }) {
        try {
          const request: EvaluateRequest = { action: params.action, resource: params.resource };
          const result = evaluateMandate(params.mandate, request);

          return {
            content: [{
              type: 'text',
              text: JSON.stringify({
                decision: result.decision,
                matchedPolicy: result.matchedPolicy ?? null,
                reason: result.reason ?? null,
              }, null, 2),
            }],
          };
        } catch (err: any) {
          return { content: [{ type: 'text', text: `Evaluate failed: ${err.message}` }], isError: true };
        }
      },
    },
    { optional: true },
  );

  // --- Tool: ovid_shadow ---
  api.registerTool(
    {
      name: 'ovid_shadow',
      label: 'OVID Shadow',
      description: 'Compare two mandates against a set of test actions. Shows what would change between current and candidate.',
      parameters: {
        type: 'object',
        required: ['currentMandate', 'candidateMandate', 'actions'],
        properties: {
          currentMandate: { type: 'string', description: 'Current Cedar policy text' },
          candidateMandate: { type: 'string', description: 'Candidate Cedar policy text' },
          actions: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                action: { type: 'string' },
                resource: { type: 'string' },
              },
              required: ['action', 'resource'],
            },
            description: 'Test actions to evaluate',
          },
        },
      },
      async execute(_toolCallId: string, params: {
        currentMandate: string;
        candidateMandate: string;
        actions: Array<{ action: string; resource: string }>;
      }) {
        try {
          const results = params.actions.map((a) => {
            const current = evaluateMandate(params.currentMandate, a);
            const candidate = evaluateMandate(params.candidateMandate, a);
            return {
              action: a.action,
              resource: a.resource,
              current: current.decision,
              candidate: candidate.decision,
              changed: current.decision !== candidate.decision,
            };
          });

          const changed = results.filter((r) => r.changed).length;

          return {
            content: [{
              type: 'text',
              text: JSON.stringify({ results, summary: { total: results.length, changed } }, null, 2),
            }],
          };
        } catch (err: any) {
          return { content: [{ type: 'text', text: `Shadow compare failed: ${err.message}` }], isError: true };
        }
      },
    },
    { optional: true },
  );

  // --- Tool: ovid_audit ---
  api.registerTool(
    {
      name: 'ovid_audit',
      label: 'OVID Audit',
      description: 'Query the OVID-ME audit database. Supports overview, agents, anomalies queries.',
      parameters: {
        type: 'object',
        required: ['query'],
        properties: {
          query: {
            type: 'string',
            enum: ['overview', 'mandates', 'agents', 'anomalies', 'recent'],
            description: 'Type of audit query',
          },
          from: { type: 'number', description: 'Start timestamp (epoch seconds, optional)' },
          to: { type: 'number', description: 'End timestamp (epoch seconds, optional)' },
        },
      },
      async execute(_toolCallId: string, params: { query: string; from?: number; to?: number }) {
        if (!auditDb) {
          return {
            content: [{ type: 'text', text: 'Audit database not configured. Set auditDb in plugin config.' }],
            isError: true,
          };
        }

        try {
          let data: unknown;
          const fromMs = params.from ? params.from * 1000 : undefined;
          const toMs = params.to ? params.to * 1000 : undefined;

          switch (params.query) {
            case 'overview':
              data = auditDb.getOverview(fromMs, toMs);
              break;
            case 'anomalies':
              data = auditDb.getAnomalies(fromMs, toMs);
              break;
            case 'recent':
            case 'agents':
            case 'mandates':
              // These map to getOverview with time range filtering
              data = auditDb.getOverview(fromMs, toMs);
              break;
            default:
              return { content: [{ type: 'text', text: `Unknown query type: ${params.query}` }], isError: true };
          }

          return {
            content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
          };
        } catch (err: any) {
          return { content: [{ type: 'text', text: `Audit query failed: ${err.message}` }], isError: true };
        }
      },
    },
    { optional: true },
  );

  // --- CLI ---
  api.registerCli?.(
    ({ program }) => {
      const cmd = program.command('ovid-me').description('OVID-ME mandate evaluation');

      cmd.command('status').action(async () => {
        console.log('\n⚖️  OVID-ME Status\n');
        console.log(`  Mode:        ${mandateMode}`);
        console.log(`  Subset:      ${config.subsetProof ?? 'off'}`);
        console.log(`  On failure:  ${config.enforcementFailure ?? 'closed'}`);
        console.log(`  Audit log:   ${config.auditLog ?? '(not configured)'}`);
        console.log(`  Audit DB:    ${auditDbPath}`);
        console.log(`  Dashboard:   ${dashboardRunning ? `http://localhost:${dashboardPort}` : '(not running)'}`);
        console.log();
      });

      cmd.command('dashboard').action(async () => {
        if (!config.auditDb) {
          console.log('\n⚠️  No auditDb configured. Set it in plugin config first.\n');
          return;
        }
        if (dashboardRunning) {
          console.log(`\n✅ Dashboard already running at http://localhost:${dashboardPort}\n`);
        } else {
          await startDashboard({ dbPath: config.auditDb, port: dashboardPort });
          dashboardRunning = true;
          console.log(`\n🔍 Dashboard started at http://localhost:${dashboardPort}\n`);
        }
      });
    },
    { commands: ['ovid-me'] },
  );
}
