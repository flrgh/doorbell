import type { GetServerSidePropsContext } from 'next';
/**
 * Send XML response, supports legacy pages directory
 * @param ctx
 * @param content
 * @returns
 */
export declare const withXMLResponseLegacy: (ctx: GetServerSidePropsContext, content: string) => {
    props: {};
};
/**
 * Send XML response, as next13+ route response
 * @param content
 * @param headers Custom request headers
 * @returns
 */
export declare const withXMLResponse: (content: string, headers?: {}) => Response;
