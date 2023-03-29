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
var __rest = (this && this.__rest) || function (s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
};
var __read = (this && this.__read) || function (o, n) {
    var m = typeof Symbol === "function" && o[Symbol.iterator];
    if (!m) return o;
    var i = m.call(o), r, ar = [], e;
    try {
        while ((n === void 0 || n-- > 0) && !(r = i.next()).done) ar.push(r.value);
    }
    catch (error) { e = { error: error }; }
    finally {
        try {
            if (r && !r.done && (m = i["return"])) m.call(i);
        }
        finally { if (e) throw e.error; }
    }
    return ar;
};
var __spreadArray = (this && this.__spreadArray) || function (to, from, pack) {
    if (pack || arguments.length === 2) for (var i = 0, l = from.length, ar; i < l; i++) {
        if (ar || !(i in from)) {
            if (!ar) ar = Array.prototype.slice.call(from, 0, i);
            ar[i] = from[i];
        }
    }
    return to.concat(ar || Array.prototype.slice.call(from));
};
var __values = (this && this.__values) || function(o) {
    var s = typeof Symbol === "function" && Symbol.iterator, m = s && o[s], i = 0;
    if (m) return m.call(o);
    if (o && typeof o.length === "number") return {
        next: function () {
            if (o && i >= o.length) o = void 0;
            return { value: o && o[i++], done: !o };
        }
    };
    throw new TypeError(s ? "Object is not iterable." : "Symbol.iterator is not defined.");
};
exports.__esModule = true;
exports.SitemapBuilder = void 0;
/**
 * Builder class to generate xml and robots.txt
 * Returns only string values
 */
var SitemapBuilder = /** @class */ (function () {
    function SitemapBuilder() {
    }
    /**
     * Create XML Template
     * @param content
     * @returns
     */
    SitemapBuilder.prototype.withXMLTemplate = function (content) {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\" xmlns:news=\"http://www.google.com/schemas/sitemap-news/0.9\" xmlns:xhtml=\"http://www.w3.org/1999/xhtml\" xmlns:mobile=\"http://www.google.com/schemas/sitemap-mobile/1.0\" xmlns:image=\"http://www.google.com/schemas/sitemap-image/1.1\" xmlns:video=\"http://www.google.com/schemas/sitemap-video/1.1\">\n".concat(content, "</urlset>");
    };
    /**
     * Generates sitemap-index.xml
     * @param allSitemaps
     * @returns
     */
    SitemapBuilder.prototype.buildSitemapIndexXml = function (allSitemaps) {
        var _a;
        return __spreadArray(__spreadArray([
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        ], __read(((_a = allSitemaps === null || allSitemaps === void 0 ? void 0 : allSitemaps.map(function (x) { return "<sitemap><loc>".concat(x, "</loc></sitemap>"); })) !== null && _a !== void 0 ? _a : [])), false), [
            '</sitemapindex>',
        ], false).join('\n');
    };
    /**
     * Normalize sitemap field keys to stay consistent with <xsd:sequence> order
     * @link https://www.w3schools.com/xml/el_sequence.asp
     * @link https://github.com/iamvishnusankar/next-sitemap/issues/345
     * @param x
     * @returns
     */
    SitemapBuilder.prototype.normalizeSitemapField = function (x) {
        var loc = x.loc, lastmod = x.lastmod, changefreq = x.changefreq, priority = x.priority, restProps = __rest(x
        // Return keys in following order
        , ["loc", "lastmod", "changefreq", "priority"]);
        // Return keys in following order
        return __assign({ loc: loc, lastmod: lastmod, changefreq: changefreq, priority: priority }, restProps);
    };
    /**
     * Composes YYYY-MM-DDThh:mm:ssTZD date format (with TZ offset)
     * (ref: https://stackoverflow.com/a/49332027)
     * @param date
     * @private
     */
    SitemapBuilder.prototype.formatDate = function (date) {
        var d = typeof date === 'string' ? new Date(date) : date;
        var z = function (n) { return ('0' + n).slice(-2); };
        var zz = function (n) { return ('00' + n).slice(-3); };
        var off = d.getTimezoneOffset();
        var sign = off > 0 ? '-' : '+';
        off = Math.abs(off);
        return (d.getFullYear() +
            '-' +
            z(d.getMonth() + 1) +
            '-' +
            z(d.getDate()) +
            'T' +
            z(d.getHours()) +
            ':' +
            z(d.getMinutes()) +
            ':' +
            z(d.getSeconds()) +
            '.' +
            zz(d.getMilliseconds()) +
            sign +
            z((off / 60) | 0) +
            ':' +
            z(off % 60));
    };
    SitemapBuilder.prototype.formatBoolean = function (value) {
        return value ? 'yes' : 'no';
    };
    SitemapBuilder.prototype.escapeHtml = function (s) {
        return s.replace(/[^\dA-Za-z ]/g, function (c) { return '&#' + c.charCodeAt(0) + ';'; });
    };
    /**
     * Generates sitemap.xml
     * @param fields
     * @returns
     */
    SitemapBuilder.prototype.buildSitemapXml = function (fields) {
        var _this = this;
        var content = fields
            .map(function (x) {
            var e_1, _a, e_2, _b, e_3, _c;
            // Normalize sitemap field keys to stay consistent with <xsd:sequence> order
            var field = _this.normalizeSitemapField(x);
            // Field array to keep track of properties
            var fieldArr = [];
            try {
                // Iterate all object keys and key value pair to field-set
                for (var _d = __values(Object.keys(field)), _e = _d.next(); !_e.done; _e = _d.next()) {
                    var key = _e.value;
                    // Skip reserved keys
                    if (['trailingSlash'].includes(key)) {
                        continue;
                    }
                    if (field[key]) {
                        if (key === 'alternateRefs') {
                            var altRefField = _this.buildAlternateRefsXml(field.alternateRefs);
                            fieldArr.push(altRefField);
                        }
                        else if (key === 'news') {
                            if (field.news) {
                                var newsField = _this.buildNewsXml(field.news);
                                fieldArr.push(newsField);
                            }
                        }
                        else if (key === 'images') {
                            if (field.images) {
                                try {
                                    for (var _f = (e_2 = void 0, __values(field.images)), _g = _f.next(); !_g.done; _g = _f.next()) {
                                        var image = _g.value;
                                        var imageField = _this.buildImageXml(image);
                                        fieldArr.push(imageField);
                                    }
                                }
                                catch (e_2_1) { e_2 = { error: e_2_1 }; }
                                finally {
                                    try {
                                        if (_g && !_g.done && (_b = _f["return"])) _b.call(_f);
                                    }
                                    finally { if (e_2) throw e_2.error; }
                                }
                            }
                        }
                        else if (key === 'videos') {
                            if (field.videos) {
                                try {
                                    for (var _h = (e_3 = void 0, __values(field.videos)), _j = _h.next(); !_j.done; _j = _h.next()) {
                                        var video = _j.value;
                                        var videoField = _this.buildVideoXml(video);
                                        fieldArr.push(videoField);
                                    }
                                }
                                catch (e_3_1) { e_3 = { error: e_3_1 }; }
                                finally {
                                    try {
                                        if (_j && !_j.done && (_c = _h["return"])) _c.call(_h);
                                    }
                                    finally { if (e_3) throw e_3.error; }
                                }
                            }
                        }
                        else {
                            fieldArr.push("<".concat(key, ">").concat(field[key], "</").concat(key, ">"));
                        }
                    }
                }
            }
            catch (e_1_1) { e_1 = { error: e_1_1 }; }
            finally {
                try {
                    if (_e && !_e.done && (_a = _d["return"])) _a.call(_d);
                }
                finally { if (e_1) throw e_1.error; }
            }
            // Append previous value and return
            return "<url>".concat(fieldArr.join(''), "</url>\n");
        })
            .join('');
        return this.withXMLTemplate(content);
    };
    /**
     * Generate alternate refs.xml
     * @param alternateRefs
     * @returns
     */
    SitemapBuilder.prototype.buildAlternateRefsXml = function (alternateRefs) {
        if (alternateRefs === void 0) { alternateRefs = []; }
        return alternateRefs
            .map(function (alternateRef) {
            return "<xhtml:link rel=\"alternate\" hreflang=\"".concat(alternateRef.hreflang, "\" href=\"").concat(alternateRef.href, "\"/>");
        })
            .join('');
    };
    /**
     * Generate Google News sitemap entry
     * @param news
     * @returns string
     */
    SitemapBuilder.prototype.buildNewsXml = function (news) {
        // using array just because it looks more structured
        return __spreadArray(__spreadArray([
            "<news:news>"
        ], __read(__spreadArray(__spreadArray([
            "<news:publication>"
        ], [
            "<news:name>".concat(this.escapeHtml(news.publicationName), "</news:name>"),
            "<news:language>".concat(news.publicationLanguage, "</news:language>"),
        ], false), [
            "</news:publication>",
            "<news:publication_date>".concat(this.formatDate(news.date), "</news:publication_date>"),
            "<news:title>".concat(this.escapeHtml(news.title), "</news:title>"),
        ], false)), false), [
            "</news:news>",
        ], false).filter(Boolean)
            .join('');
    };
    /**
     * Generate Image sitemap entry
     * @param image
     * @returns string
     */
    SitemapBuilder.prototype.buildImageXml = function (image) {
        // using array just because it looks more structured
        return __spreadArray(__spreadArray([
            "<image:image>"
        ], [
            "<image:loc>".concat(image.loc.href, "</image:loc>"),
            image.caption &&
                "<image:caption>".concat(this.escapeHtml(image.caption), "</image:caption>"),
            image.title &&
                "<image:title>".concat(this.escapeHtml(image.title), "</image:title>"),
            image.geoLocation &&
                "<image:geo_location>".concat(this.escapeHtml(image.geoLocation), "</image:geo_location>"),
            image.license && "<image:license>".concat(image.license.href, "</image:license>"),
        ], false), [
            "</image:image>",
        ], false).filter(Boolean)
            .join('');
    };
    /**
     * Generate Video sitemap entry
     * @param video
     * @returns string
     */
    SitemapBuilder.prototype.buildVideoXml = function (video) {
        // using array just because it looks more structured
        return __spreadArray(__spreadArray([
            "<video:video>"
        ], [
            "<video:title>".concat(this.escapeHtml(video.title), "</video:title>"),
            "<video:thumbnail_loc>".concat(video.thumbnailLoc.href, "</video:thumbnail_loc>"),
            "<video:description>".concat(this.escapeHtml(video.description), "</video:description>"),
            video.contentLoc &&
                "<video:content_loc>".concat(video.contentLoc.href, "</video:content_loc>"),
            video.playerLoc &&
                "<video:player_loc>".concat(video.playerLoc.href, "</video:player_loc>"),
            video.duration && "<video:duration>".concat(video.duration, "</video:duration>"),
            video.viewCount &&
                "<video:view_count>".concat(video.viewCount, "</video:view_count>"),
            video.tag && "<video:tag>".concat(this.escapeHtml(video.tag), "</video:tag>"),
            video.rating &&
                "<video:rating>".concat(video.rating
                    .toFixed(1)
                    .replace(',', '.'), "</video:rating>"),
            video.expirationDate &&
                "<video:expiration_date>".concat(this.formatDate(video.expirationDate), "</video:expiration_date>"),
            video.publicationDate &&
                "<video:publication_date>".concat(this.formatDate(video.publicationDate), "</video:publication_date>"),
            typeof video.familyFriendly !== 'undefined' &&
                "<video:family_friendly>".concat(this.formatBoolean(video.familyFriendly), "</video:family_friendly>"),
            typeof video.requiresSubscription !== 'undefined' &&
                "<video:requires_subscription>".concat(this.formatBoolean(video.requiresSubscription), "</video:requires_subscription>"),
            typeof video.live !== 'undefined' &&
                "<video:live>".concat(this.formatBoolean(video.live), "</video:live>"),
            video.restriction &&
                "<video:restriction relationship=\"".concat(video.restriction.relationship, "\">").concat(video.restriction.content, "</video:restriction>"),
            video.platform &&
                "<video:platform relationship=\"".concat(video.platform.relationship, "\">").concat(video.platform.content, "</video:platform>"),
            video.uploader &&
                "<video:uploader".concat(video.uploader.info && " info=\"".concat(video.uploader.info, "\""), ">").concat(this.escapeHtml(video.uploader.name), "</video:uploader>"),
        ], false), [
            "</video:video>",
        ], false).filter(Boolean)
            .join('');
    };
    return SitemapBuilder;
}());
exports.SitemapBuilder = SitemapBuilder;
