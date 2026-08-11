import type { CreateInboundOptions, SingBoxCoreConfig, SingBoxDns, SingBoxDnsRule, SingBoxDnsServer, SingBoxExperimental, SingBoxOutbound, SingBoxRoute, SingBoxRouteRule, SingBoxRuleSet, SingBoxValidationIssue, SingBoxVersion } from "./types.js";
export type SingBoxCertMode = "path" | "content";
/** Masquerade long-form kind. "" keeps the bare-URL string shorthand (`masquerade`). */
export type SingBoxMasqueradeType = "" | "file" | "proxy" | "string";
export type SingBoxTransportType = "" | "ws" | "grpc" | "http" | "httpupgrade";
/** The protocols the sing-box core editor can create. */
export type SingBoxProtocol = "vless" | "vmess" | "trojan" | "shadowsocks" | "tuic" | "hysteria2";
type EchDraftFields = {
    readonly echEnabled: boolean;
    readonly echKey: string;
    readonly echPqSignatureSchemesEnabled: boolean;
    readonly echDynamicRecordSizingDisabled: boolean;
};
type AcmeDraftFields = {
    readonly acmeEnabled: boolean;
    readonly acmeDomain: readonly string[];
    readonly acmeEmail: string;
    readonly acmeProvider: string;
    readonly acmeDns01Provider: string;
    readonly acmeDns01ApiToken: string;
    readonly acmeDns01AccessKeyId: string;
    readonly acmeDns01AccessKeySecret: string;
};
/** Shared TLS form fields (superset used by vless/vmess/trojan/tuic; also structurally covers hysteria2). */
export type TlsDraftFields = EchDraftFields & AcmeDraftFields & {
    readonly tlsEnabled: boolean;
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
    readonly utlsEnabled: boolean;
    readonly utlsFingerprint: string;
    readonly realityEnabled: boolean;
    readonly realityHandshakeServer: string;
    readonly realityHandshakePort: string;
    readonly realityPrivateKey: string;
    readonly realityShortId: readonly string[];
    readonly realityMaxTimeDifference: string;
};
/** Shared V2Ray transport form fields (vless/vmess/trojan). */
export type TransportDraftFields = {
    readonly transportType: SingBoxTransportType;
    readonly transportPath: string;
    readonly transportHost: string;
    readonly transportServiceName: string;
    readonly transportMethod: string;
};
type InboundBaseDraft = {
    readonly tag: string;
    readonly listen: string;
    readonly listenPort: number | string;
};
export type VlessInboundDraft = InboundBaseDraft & TlsDraftFields & TransportDraftFields & {
    readonly protocol: "vless";
};
export type VmessInboundDraft = InboundBaseDraft & TlsDraftFields & TransportDraftFields & {
    readonly protocol: "vmess";
};
export type TrojanInboundDraft = InboundBaseDraft & TlsDraftFields & TransportDraftFields & {
    readonly protocol: "trojan";
};
export type TuicInboundDraft = InboundBaseDraft & TlsDraftFields & {
    readonly protocol: "tuic";
    readonly congestionControl: string;
};
export type ShadowsocksInboundDraft = InboundBaseDraft & {
    readonly protocol: "shadowsocks";
    readonly method: string;
    readonly password: string;
};
/**
 * Form-state shape for a single Hysteria2 inbound. `certMode` is UI-only. Unchanged from the
 * original Hysteria2-only kit except for the `protocol` discriminant added for the union.
 */
export type HysteriaInboundDraft = {
    readonly protocol: "hysteria2";
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
export type SingBoxInboundDraft = VlessInboundDraft | VmessInboundDraft | TrojanInboundDraft | ShadowsocksInboundDraft | TuicInboundDraft | HysteriaInboundDraft;
export type SingBoxCoreDraft = {
    readonly logLevel: string;
    /** sing-box release the config targets (drives the DNS-server + route-action shape). Default 1.12. */
    readonly singboxVersion: SingBoxVersion;
    readonly inbounds: readonly SingBoxInboundDraft[];
    /**
     * Outbounds/route/dns/experimental are stored WIRE-SHAPED (snake_case, exactly what sing-box
     * consumes). The dashboard section editors read/write these objects directly and the core
     * builder spreads them verbatim, so anything the UI doesn't model round-trips untouched.
     * Rule Sets live inside `route.rule_set`; Balancers are the `selector`/`urltest` outbounds.
     */
    readonly outbounds: readonly SingBoxOutbound[];
    readonly route: SingBoxRoute;
    readonly dns: SingBoxDns;
    readonly experimental: SingBoxExperimental;
};
export declare function createDefaultVlessInboundDraft(existingTags?: readonly string[]): VlessInboundDraft;
export declare function createDefaultVmessInboundDraft(existingTags?: readonly string[]): VmessInboundDraft;
export declare function createDefaultTrojanInboundDraft(existingTags?: readonly string[]): TrojanInboundDraft;
export declare function createDefaultTuicInboundDraft(existingTags?: readonly string[]): TuicInboundDraft;
export declare function createDefaultShadowsocksInboundDraft(existingTags?: readonly string[]): ShadowsocksInboundDraft;
export declare function createDefaultHysteria2InboundDraft(existingTags?: readonly string[]): HysteriaInboundDraft;
/** Default draft for a given protocol (used by the "add inbound" / protocol-switch flows). */
export declare function createDefaultInboundDraft(protocol: SingBoxProtocol, existingTags?: readonly string[]): SingBoxInboundDraft;
export declare function createDefaultSingBoxCoreDraft(): SingBoxCoreDraft;
/** Outbound types the sing-box editor can add. `block`/`dns` are legacy (route actions ≥1.11). */
export declare const SINGBOX_OUTBOUND_TYPES: readonly ["direct", "block", "socks", "http", "shadowsocks", "vmess", "vless", "trojan", "hysteria2", "tuic", "anytls", "ssh", "dns", "selector", "urltest"];
export type SingBoxOutboundType = (typeof SINGBOX_OUTBOUND_TYPES)[number];
/** selector/urltest outbounds are the "balancers" of sing-box (member picking). */
export declare const SINGBOX_BALANCER_OUTBOUND_TYPES: readonly SingBoxOutboundType[];
export declare function createDefaultSingBoxOutbound(type: SingBoxOutboundType, existingTags?: readonly string[]): SingBoxOutbound;
export declare function createDefaultSingBoxRouteRule(): SingBoxRouteRule;
export declare const SINGBOX_RULE_SET_TYPES: readonly ["remote", "local", "inline"];
export type SingBoxRuleSetType = (typeof SINGBOX_RULE_SET_TYPES)[number];
export declare function createDefaultSingBoxRuleSet(type: SingBoxRuleSetType, existingTags?: readonly string[]): SingBoxRuleSet;
/** DNS server default. 1.12 uses typed servers ({type,server}); 1.11 uses {address}. */
export declare function createDefaultSingBoxDnsServer(version: SingBoxVersion, existingTags?: readonly string[]): SingBoxDnsServer;
export declare function createDefaultSingBoxDnsRule(): SingBoxDnsRule;
export declare function inboundOptionsFromDraft(draft: SingBoxInboundDraft): CreateInboundOptions;
export declare function validateInboundDraft(draft: SingBoxInboundDraft, index: number, allTags: readonly string[]): SingBoxValidationIssue[];
/** Mirrors the validation.ts semantic rules for hysteria2, at the draft/form level. */
export declare function validateHysteria2InboundDraft(draft: HysteriaInboundDraft, index: number, allTags: readonly string[]): SingBoxValidationIssue[];
export declare function validateSingBoxCoreDraft(draft: SingBoxCoreDraft): SingBoxValidationIssue[];
export declare function createSingBoxCoreConfigFromDraft(draft: SingBoxCoreDraft): SingBoxCoreConfig;
export declare function generateSingBoxCoreConfigJsonFromDraft(draft: SingBoxCoreDraft, space?: number): string;
/** Exposed for callers that build a single inbound's config JSON without a full draft (e.g. previews). */
export declare function createInboundConfigFromDraft(draft: SingBoxInboundDraft): import("./types.js").SingBoxInbound;
/** Back-compat alias for the original single-protocol export name. */
export declare function createHysteria2InboundConfigFromDraft(draft: HysteriaInboundDraft): import("./types.js").SingBoxHysteria2Inbound;
export {};
//# sourceMappingURL=form.d.ts.map