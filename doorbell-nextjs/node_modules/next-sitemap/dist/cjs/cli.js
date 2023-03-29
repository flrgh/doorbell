"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
exports.__esModule = true;
exports.CLI = void 0;
/* eslint-disable @typescript-eslint/no-non-null-assertion */
var logger_js_1 = require("./logger.js");
var array_js_1 = require("./utils/array.js");
var config_parser_js_1 = require("./parsers/config-parser.js");
var manifest_parser_js_1 = require("./parsers/manifest-parser.js");
var url_set_builder_js_1 = require("./builders/url-set-builder.js");
var exportable_builder_js_1 = require("./builders/exportable-builder.js");
var CLI = /** @class */ (function () {
    function CLI() {
    }
    /**
     * Main method
     * @returns
     */
    CLI.prototype.main = function () {
        return __awaiter(this, void 0, void 0, function () {
            var _a, config, runtimePaths, manifest, urlSet, chunks, expoBuilder;
            return __generator(this, function (_b) {
                switch (_b.label) {
                    case 0: return [4 /*yield*/, new config_parser_js_1.ConfigParser().loadConfig()
                        // Load next.js manifest
                    ];
                    case 1:
                        _a = _b.sent(), config = _a.config, runtimePaths = _a.runtimePaths;
                        return [4 /*yield*/, new manifest_parser_js_1.ManifestParser().loadManifest(runtimePaths)
                            // Generate url set
                        ];
                    case 2:
                        manifest = _b.sent();
                        return [4 /*yield*/, new url_set_builder_js_1.UrlSetBuilder(config, manifest).createUrlSet()
                            // Split sitemap into multiple files
                        ];
                    case 3:
                        urlSet = _b.sent();
                        chunks = (0, array_js_1.toChunks)(urlSet, config.sitemapSize);
                        expoBuilder = new exportable_builder_js_1.ExportableBuilder(config, runtimePaths);
                        // Register sitemap exports
                        return [4 /*yield*/, expoBuilder.registerSitemaps(chunks)
                            // Register index sitemap if user config allows generation
                        ];
                    case 4:
                        // Register sitemap exports
                        _b.sent();
                        if (!config.generateIndexSitemap) return [3 /*break*/, 6];
                        return [4 /*yield*/, expoBuilder.registerIndexSitemap()];
                    case 5:
                        _b.sent();
                        _b.label = 6;
                    case 6:
                        if (!(config === null || config === void 0 ? void 0 : config.generateRobotsTxt)) return [3 /*break*/, 8];
                        return [4 /*yield*/, expoBuilder.registerRobotsTxt()];
                    case 7:
                        _b.sent();
                        _b.label = 8;
                    case 8: 
                    // Export all files
                    return [2 /*return*/, expoBuilder.exportAll()];
                }
            });
        });
    };
    /**
     * Execute and log result
     * @returns
     */
    CLI.prototype.execute = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this.main().then(logger_js_1.Logger.generationCompleted)];
            });
        });
    };
    return CLI;
}());
exports.CLI = CLI;
