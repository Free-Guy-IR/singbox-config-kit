import type { SingBoxCoreConfig, SingBoxValidationIssue } from "./types.js";
export type SingBoxCertMode = "path" | "content";
/**
 * Form-state shape for a single Hysteria2 inbound, distinct from the persisted JSON shape.
 * `certMode` is UI-only: it decides whether `certificateFile`/`keyFile` (-> certificate_path/
 * key_path) or `certificate`/`key` (-> inline PEM content) are serialized on save, mirroring
 * the existing Xray inbound TLS certificate path/content toggle.
 */
/** Masquerade long-form kind. "" keeps the bare-URL string shorthand (`masquerade`). */
export type SingBoxMasqueradeType = "" | "file" | "proxy" | "string";
export type HysteriaInboundDraft = {
    readonly tag: string;
    readonly listen: string;
    readonly listenPort: number | string;
    readonly upMbps: string;
    readonly downMbps: string;
    readonly ignoreClientBandwidth: boolean;
    readonly udpTimeout: string;
    readonly udpFragment: boolean;
    readonly brutalDebug: boolean;
    readonly portHoppingRange: string;
    readonly obfsEnabled: boolean;
    readonly obfsPassword: string;
    readonly masquerade: string;
    readonly masqueradeType: SingBoxMasqueradeType;
    readonly masqueradeDirectory: string;
    readonly masqueradeRewriteHost: boolean;
    readonly masqueradeStatusCode: string;
    readonly masqueradeHeaders: string;
    readonly masqueradeContent: string;
    readonly tlsServerName: string;
    readonly tlsAlpn: readonly string[];
    readonly tlsMinVersion: string;
    readonly tlsMaxVersion: string;
    readonly tlsCipherSuites: readonly string[];
    readonly certMode: SingBoxCertMode;
    readonly certificateFile: string;
    readonly keyFile: string;
    readonly certificate: string;
    readonly key: string;
    readonly echEnabled: boolean;
    readonly echKey: string;
    readonly echPqSignatureSchemesEnabled: boolean;
    readonly echDynamicRecordSizingDisabled: boolean;
    readonly acmeEnabled: boolean;
    readonly acmeDomain: readonly string[];
    readonly acmeEmail: string;
    readonly acmeProvider: string;
    readonly acmeDns01Provider: string;
    readonly acmeDns01ApiToken: string;
    readonly acmeDns01AccessKeyId: string;
    readonly acmeDns01AccessKeySecret: string;
};
export type SingBoxCoreDraft = {
    readonly logLevel: string;
    readonly inbounds: readonly HysteriaInboundDraft[];
};
export declare function createDefaultHysteria2InboundDraft(existingTags?: readonly string[]): HysteriaInboundDraft;
export declare function createDefaultSingBoxCoreDraft(): SingBoxCoreDraft;
/** Mirrors the validation.ts semantic rules, at the draft/form level (pre-serialization). */
export declare function validateHysteria2InboundDraft(draft: HysteriaInboundDraft, index: number, allTags: readonly string[]): SingBoxValidationIssue[];
export declare function validateSingBoxCoreDraft(draft: SingBoxCoreDraft): SingBoxValidationIssue[];
export declare function createSingBoxCoreConfigFromDraft(draft: SingBoxCoreDraft): SingBoxCoreConfig;
export declare function generateSingBoxCoreConfigJsonFromDraft(draft: SingBoxCoreDraft, space?: number): string;
/** Exposed for callers that build a single inbound's config JSON without a full draft (e.g. previews). */
export declare function createHysteria2InboundConfigFromDraft(draft: HysteriaInboundDraft): import("./types.js").SingBoxHysteria2Inbound;
//# sourceMappingURL=form.d.ts.map