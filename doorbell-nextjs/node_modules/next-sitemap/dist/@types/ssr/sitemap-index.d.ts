import type { GetServerSidePropsContext } from 'next';
/**
 * Generate index sitemaps on server side, support pages directory
 * @param ctx
 * @param sitemaps
 * @returns
 */
export declare const getServerSideSitemapIndexLegacy: (ctx: GetServerSidePropsContext, sitemaps: string[]) => Promise<{
    props: {};
}>;
/**
 * Generate index sitemaps on server side, support next13+ route.{ts,js} file.
 * To continue using inside pages directory, import `getServerSideSitemapIndexLegacy` instead.
 * @param sitemaps
 * @param headers Custom request headers
 * @returns
 */
export declare const getServerSideSitemapIndex: (sitemaps: string[], headers?: {}) => Promise<Response>;
