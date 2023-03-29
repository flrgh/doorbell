import type { IAlternateRef, IGoogleNewsEntry, IImageEntry, ISitemapField, IVideoEntry } from '../interface.js';
/**
 * Builder class to generate xml and robots.txt
 * Returns only string values
 */
export declare class SitemapBuilder {
    /**
     * Create XML Template
     * @param content
     * @returns
     */
    withXMLTemplate(content: string): string;
    /**
     * Generates sitemap-index.xml
     * @param allSitemaps
     * @returns
     */
    buildSitemapIndexXml(allSitemaps: string[]): string;
    /**
     * Normalize sitemap field keys to stay consistent with <xsd:sequence> order
     * @link https://www.w3schools.com/xml/el_sequence.asp
     * @link https://github.com/iamvishnusankar/next-sitemap/issues/345
     * @param x
     * @returns
     */
    normalizeSitemapField(x: ISitemapField): {
        alternateRefs?: IAlternateRef[] | undefined;
        trailingSlash?: boolean | undefined;
        news?: IGoogleNewsEntry | undefined;
        images?: IImageEntry[] | undefined;
        videos?: IVideoEntry[] | undefined;
        loc: string;
        lastmod: string | undefined;
        changefreq: ("always" | "hourly" | "daily" | "weekly" | "monthly" | "yearly" | "never") | undefined;
        priority: number | undefined;
    };
    /**
     * Composes YYYY-MM-DDThh:mm:ssTZD date format (with TZ offset)
     * (ref: https://stackoverflow.com/a/49332027)
     * @param date
     * @private
     */
    private formatDate;
    private formatBoolean;
    private escapeHtml;
    /**
     * Generates sitemap.xml
     * @param fields
     * @returns
     */
    buildSitemapXml(fields: ISitemapField[]): string;
    /**
     * Generate alternate refs.xml
     * @param alternateRefs
     * @returns
     */
    buildAlternateRefsXml(alternateRefs?: Array<IAlternateRef>): string;
    /**
     * Generate Google News sitemap entry
     * @param news
     * @returns string
     */
    buildNewsXml(news: IGoogleNewsEntry): string;
    /**
     * Generate Image sitemap entry
     * @param image
     * @returns string
     */
    buildImageXml(image: IImageEntry): string;
    /**
     * Generate Video sitemap entry
     * @param video
     * @returns string
     */
    buildVideoXml(video: IVideoEntry): string;
}
