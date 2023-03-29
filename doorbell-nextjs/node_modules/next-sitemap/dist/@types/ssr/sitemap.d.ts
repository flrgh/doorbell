import type { GetServerSidePropsContext } from 'next';
import type { ISitemapField } from '../interface.js';
/**
 * Generate server side sitemaps, supports legacy pages directory
 * @param ctx
 * @param fields
 * @returns
 */
export declare const getServerSideSitemapLegacy: (ctx: GetServerSidePropsContext, fields: ISitemapField[]) => Promise<{
    props: {};
}>;
/**
 * Generate server side sitemaps, support next13+ route.{ts,js} file.
 * To continue using inside pages directory, import `getServerSideSitemapLegacy` instead.
 * @param fields
 * @param headers Custom request headers
 * @returns
 */
export declare const getServerSideSitemap: (fields: ISitemapField[], headers?: {}) => Promise<Response>;
