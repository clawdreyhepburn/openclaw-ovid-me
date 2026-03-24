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
  type OvidConfig,
  type EvaluateRequest,
} from '@clawdreyhepburn/ovid-me';

export const id = 'ovid-me';
export const name = 'OVID-ME';

interface PluginConfig {
  mandateMode?: 'enforce' | 'dry-run' | 'shadow';
  auditLog?: string;
  auditDb?: string;
  dashboardPort?: number;
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
}

let engine: MandateEngine | null = null;
let auditDb: AuditDatabase | null = null;
let dashboardRunning = false;

export default function register(api: OpenClawPluginApi) {
  const config: PluginConfig = api.pluginConfig ?? {};
  const logger = api.logger;

  const mandateMode = config.mandateMode ?? 'dry-run';
  const dashboardPort = config.dashboardPort ?? 19831;

  // --- Service ---
  api.registerService({
    id: 'ovid-me',
    async start() {
      const ovidConfig: Partial<OvidConfig> = {
        mandateMode,
        auditLog: config.auditLog ?? null,
        auditDb: config.auditDb ?? null,
        dashboardPort,
        subsetProof: config.subsetProof ?? 'off',
        enforcementFailure: config.enforcementFailure ?? 'closed',
      };

      engine = new MandateEngine(ovidConfig);

      if (config.auditDb) {
        auditDb = new AuditDatabase(config.auditDb);
        await startDashboard({ dbPath: config.auditDb, port: dashboardPort });
        dashboardRunning = true;
        logger.info(`OVID-ME forensics dashboard at http://localhost:${dashboardPort}`);
      }

      logger.info(`OVID-ME mandate evaluation active (mode: ${mandateMode})`);
      logger.warn('OVID-ME mandate evaluation active but no identity plugin found. Install @clawdreyhepburn/openclaw-ovid for token minting.');
    },
    async stop() {
      if (dashboardRunning) {
        await stopDashboard();
        dashboardRunning = false;
      }
    },
  });

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
        console.log(`  Audit DB:    ${config.auditDb ?? '(not configured)'}`);
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
