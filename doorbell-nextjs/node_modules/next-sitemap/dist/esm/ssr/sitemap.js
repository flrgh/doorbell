import { withXMLResponseLegacy, withXMLResponse } from './response.js';
import { SitemapBuilder } from '../builders/sitemap-builder.js';
/**
 * Generate server side sitemaps, supports legacy pages directory
 * @param ctx
 * @param fields
 * @returns
 */
export const getServerSideSitemapLegacy = async (ctx, fields) => {
    // Generate sitemap xml
    const contents = new SitemapBuilder().buildSitemapXml(fields);
    // Send response
    return withXMLResponseLegacy(ctx, contents);
};
/**
 * Generate server side sitemaps, support next13+ route.{ts,js} file.
 * To continue using inside pages directory, import `getServerSideSitemapLegacy` instead.
 * @param fields
 * @param headers Custom request headers
 * @returns
 */
export const getServerSideSitemap = async (fields, headers = {}) => {
    // Generate sitemap xml
    const contents = new SitemapBuilder().buildSitemapXml(fields);
    // Send response
    return withXMLResponse(contents, headers);
};
