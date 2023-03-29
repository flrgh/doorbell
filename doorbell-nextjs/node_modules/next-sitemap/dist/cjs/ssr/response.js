"use strict";
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
exports.__esModule = true;
exports.withXMLResponse = exports.withXMLResponseLegacy = void 0;
/**
 * Send XML response, supports legacy pages directory
 * @param ctx
 * @param content
 * @returns
 */
var withXMLResponseLegacy = function (ctx, content) {
    if (ctx === null || ctx === void 0 ? void 0 : ctx.res) {
        var res = ctx.res;
        // Set header
        res.setHeader('Content-Type', 'text/xml');
        // Write the sitemap context to resonse
        res.write(content);
        // End response
        res.end();
    }
    // Empty props
    return {
        props: {}
    };
};
exports.withXMLResponseLegacy = withXMLResponseLegacy;
/**
 * Send XML response, as next13+ route response
 * @param content
 * @param headers Custom request headers
 * @returns
 */
var withXMLResponse = function (content, headers) {
    if (headers === void 0) { headers = {}; }
    return new Response(content, {
        status: 200,
        headers: __assign({ 'Content-Type': 'text/xml' }, headers)
    });
};
exports.withXMLResponse = withXMLResponse;
