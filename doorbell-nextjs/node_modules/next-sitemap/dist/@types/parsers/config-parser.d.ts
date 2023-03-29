import type { IConfig, IRuntimePaths } from '../interface.js';
export declare class ConfigParser {
    /**
     * Get runtime config
     * @param runtimePaths
     * @returns
     */
    private getRuntimeConfig;
    /**
     * Update existing config with runtime config
     * @param config
     * @param runtimePaths
     * @returns
     */
    private withRuntimeConfig;
    /**
     * Load next-sitemap.config.js as module
     * @returns
     */
    private loadBaseConfig;
    /**
     * Load full config
     * @returns
     */
    loadConfig(): Promise<{
        config: IConfig;
        runtimePaths: IRuntimePaths;
    }>;
}
