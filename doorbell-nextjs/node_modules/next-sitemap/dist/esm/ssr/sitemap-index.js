import { SitemapBuilder } from '../builders/sitemap-builder.js';
import { withXMLResponseLegacy, withXMLResponse } from './response.js';
/**
 * Generate index sitemaps on server side, support pages directory
 * @param ctx
 * @param sitemaps
 * @returns
 */
export const getServerSideSitemapIndexLegacy = async (ctx, sitemaps) => {
    // Generate index sitemap xml content
    const indexContents = new SitemapBuilder().buildSitemapIndexXml(sitemaps);
    // Return response
    return withXMLResponseLegacy(ctx, indexContents);
};
/**
 * Generate index sitemaps on server side, support next13+ route.{ts,js} file.
 * To continue using inside pages directory, import `getServerSideSitemapIndexLegacy` instead.
 * @param sitemaps
 * @param headers Custom request headers
 * @returns
 */
export const getServerSideSitemapIndex = async (sitemaps, headers = {}) => {
    // Generate index sitemap xml content
    const indexContents = new SitemapBuilder().buildSitemapIndexXml(sitemaps);
    // Return response
    return withXMLResponse(indexContents, headers);
};
