/**
 * OpenClaw OVID-ME Plugin — Mandate evaluation tools
 */
export declare const id = "openclaw-ovid-me";
export declare const name = "OVID-ME";
interface OpenClawPluginApi {
    pluginConfig: any;
    logger: {
        info(msg: string, ...args: any[]): void;
        warn(msg: string, ...args: any[]): void;
        error(msg: string, ...args: any[]): void;
    };
    registerService(service: {
        id: string;
        start(): Promise<void> | void;
        stop(): Promise<void> | void;
    }): void;
    registerTool(tool: {
        name: string;
        label?: string;
        description: string;
        parameters: Record<string, any>;
        execute(toolCallId: string, params: any): Promise<any>;
    }, opts?: {
        optional?: boolean;
    }): void;
    registerCli?(fn: (ctx: {
        program: any;
    }) => void, opts?: {
        commands: string[];
    }): void;
    on?(hookName: string, handler: (...args: any[]) => any, opts?: {
        name?: string;
        description?: string;
    }): void;
}
export default function register(api: OpenClawPluginApi): void;
export {};
