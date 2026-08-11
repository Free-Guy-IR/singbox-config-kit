import {
  createHysteria2InboundConfig,
  createInboundConfig,
  createSingBoxCoreConfig
} from "./core.js";
import type {
  CreateInboundOptions,
  CreateTlsOptions,
  CreateTransportOptions,
  JsonObject,
  JsonValue,
  SingBoxCoreConfig,
  SingBoxDns,
  SingBoxDnsRule,
  SingBoxDnsServer,
  SingBoxExperimental,
  SingBoxOutbound,
  SingBoxRoute,
  SingBoxRouteRule,
  SingBoxRuleSet,
  SingBoxValidationIssue,
  SingBoxVersion
} from "./types.js";

export type SingBoxCertMode = "path" | "content";
/** Masquerade long-form kind. "" keeps the bare-URL string shorthand (`masquerade`). */
export type SingBoxMasqueradeType = "" | "file" | "proxy" | "string";
export type SingBoxTransportType = "" | "ws" | "grpc" | "http" | "httpupgrade";

/** The protocols the sing-box core editor can create. */
export type SingBoxProtocol = "vless" | "vmess" | "trojan" | "shadowsocks" | "tuic" | "hysteria2";

// ---------------------------------------------------------------------------
// Shared draft field groups (flat, composed into the per-protocol drafts so the
// dashboard can render one TLS/transport form component across every protocol).
// ---------------------------------------------------------------------------

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
export type TlsDraftFields = EchDraftFields &
  AcmeDraftFields & {
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
    // uTLS
    readonly utlsEnabled: boolean;
    readonly utlsFingerprint: string;
    // REALITY (mutually exclusive with certificate/acme)
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

// ---------------------------------------------------------------------------
// Per-protocol drafts (discriminated union over `protocol`).
// ---------------------------------------------------------------------------

export type VlessInboundDraft = InboundBaseDraft & TlsDraftFields & TransportDraftFields & { readonly protocol: "vless" };
export type VmessInboundDraft = InboundBaseDraft & TlsDraftFields & TransportDraftFields & { readonly protocol: "vmess" };
export type TrojanInboundDraft = InboundBaseDraft & TlsDraftFields & TransportDraftFields & { readonly protocol: "trojan" };
export type TuicInboundDraft = InboundBaseDraft & TlsDraftFields & { readonly protocol: "tuic"; readonly congestionControl: string };
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

export type SingBoxInboundDraft =
  | VlessInboundDraft
  | VmessInboundDraft
  | TrojanInboundDraft
  | ShadowsocksInboundDraft
  | TuicInboundDraft
  | HysteriaInboundDraft;

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

function issue(path: string, code: string, message: string): SingBoxValidationIssue {
  return { path, code, message };
}

function parseListenPort(value: number | string): number | undefined {
  if (typeof value === "number") return Number.isInteger(value) ? value : undefined;
  const trimmed = value.trim();
  if (!/^\d+$/.test(trimmed)) return undefined;
  return Number(trimmed);
}

function randomPort(): number {
  return Math.floor(Math.random() * (65535 - 10000 + 1)) + 10000;
}

function uniqueDefaultTag(base: string, existingTags: readonly string[]): string {
  const taken = new Set(existingTags.map(t => t.trim()));
  if (!taken.has(base)) return base;
  let n = 2;
  while (taken.has(`${base}_${n}`)) n += 1;
  return `${base}_${n}`;
}

const SHADOWSOCKS_DEFAULT_METHOD = "2022-blake3-aes-128-gcm";

// ---------------------------------------------------------------------------
// Shared draft helpers (structural over the field groups above).
// ---------------------------------------------------------------------------

function linesToArray(text: string): string[] {
  return text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
}

/** True when `text` parses to a plain JSON object (used for masquerade string headers). */
function isJsonObject(text: string): boolean {
  try {
    const parsed = JSON.parse(text);
    return !!parsed && typeof parsed === "object" && !Array.isArray(parsed);
  } catch {
    return false;
  }
}

function parseHeaders(text: string): JsonObject | undefined {
  const trimmed = text.trim();
  if (!trimmed || !isJsonObject(trimmed)) return undefined;
  return JSON.parse(trimmed) as JsonObject;
}

/** Builds the tls.ech object, or undefined when ECH is off. */
function buildEch(draft: EchDraftFields): JsonObject | undefined {
  if (!draft.echEnabled) return undefined;
  const ech: Record<string, JsonValue> = { enabled: true };
  const key = linesToArray(draft.echKey);
  if (key.length > 0) ech.key = key;
  if (draft.echPqSignatureSchemesEnabled) ech.pq_signature_schemes_enabled = true;
  if (draft.echDynamicRecordSizingDisabled) ech.dynamic_record_sizing_disabled = true;
  return ech;
}

/** Builds the tls.acme object, or undefined when ACME is off. */
function buildAcme(draft: AcmeDraftFields): JsonObject | undefined {
  if (!draft.acmeEnabled) return undefined;
  const acme: Record<string, JsonValue> = {};
  const domains = draft.acmeDomain.map(d => d.trim()).filter(Boolean);
  if (domains.length > 0) acme.domain = domains;
  if (draft.acmeEmail.trim()) acme.email = draft.acmeEmail.trim();
  if (draft.acmeProvider.trim()) acme.provider = draft.acmeProvider.trim();
  if (draft.acmeDns01Provider === "cloudflare" && draft.acmeDns01ApiToken.trim()) {
    acme.dns01_challenge = { provider: "cloudflare", api_token: draft.acmeDns01ApiToken.trim() };
  } else if (draft.acmeDns01Provider === "alidns" && draft.acmeDns01AccessKeyId.trim()) {
    acme.dns01_challenge = {
      provider: "alidns",
      access_key_id: draft.acmeDns01AccessKeyId.trim(),
      access_key_secret: draft.acmeDns01AccessKeySecret.trim()
    };
  }
  return acme;
}

/** Builds the tls.utls object, or undefined when uTLS is off. */
function buildUtls(f: TlsDraftFields): JsonObject | undefined {
  if (!f.utlsEnabled) return undefined;
  const utls: Record<string, JsonValue> = { enabled: true };
  if (f.utlsFingerprint.trim()) utls.fingerprint = f.utlsFingerprint.trim();
  return utls;
}

/** Builds the tls.reality object, or undefined when REALITY is off. */
function buildReality(f: TlsDraftFields): JsonObject | undefined {
  if (!f.realityEnabled) return undefined;
  const reality: Record<string, JsonValue> = {
    enabled: true,
    handshake: {
      server: f.realityHandshakeServer.trim(),
      server_port: f.realityHandshakePort.trim() ? Number(f.realityHandshakePort.trim()) : 443
    },
    private_key: f.realityPrivateKey.trim()
  };
  const shortIds = f.realityShortId.map(s => s.trim()).filter(Boolean);
  if (shortIds.length > 0) reality.short_id = shortIds;
  if (f.realityMaxTimeDifference.trim()) reality.max_time_difference = f.realityMaxTimeDifference.trim();
  return reality;
}

/** Converts the shared TLS draft fields into the camelCase CreateTlsOptions the builders take. */
function tlsOptionsFromDraft(f: TlsDraftFields): CreateTlsOptions {
  if (!f.tlsEnabled) return { enabled: false };
  const alpn = f.tlsAlpn.map(v => v.trim()).filter(Boolean);
  const cipherSuites = f.tlsCipherSuites.map(v => v.trim()).filter(Boolean);
  const tls: {
    enabled: boolean;
    serverName?: string;
    alpn?: readonly string[];
    minVersion?: string;
    maxVersion?: string;
    cipherSuites?: readonly string[];
    certificatePath?: string;
    keyPath?: string;
    certificate?: string | readonly string[];
    key?: string | readonly string[];
    ech?: JsonObject;
    acme?: JsonObject;
    utls?: JsonObject;
    reality?: JsonObject;
  } = { enabled: true };
  if (f.tlsServerName.trim()) tls.serverName = f.tlsServerName.trim();
  if (alpn.length > 0) tls.alpn = alpn;
  if (f.tlsMinVersion.trim()) tls.minVersion = f.tlsMinVersion.trim();
  if (f.tlsMaxVersion.trim()) tls.maxVersion = f.tlsMaxVersion.trim();
  if (cipherSuites.length > 0) tls.cipherSuites = cipherSuites;

  const reality = buildReality(f);
  const acme = buildAcme(f);
  // REALITY, ACME and an explicit certificate are mutually exclusive; sing-box rejects a mix.
  if (reality) {
    tls.reality = reality;
  } else if (acme) {
    tls.acme = acme;
  } else if (f.certMode === "content") {
    tls.certificate = linesToArray(f.certificate);
    tls.key = linesToArray(f.key);
  } else {
    tls.certificatePath = f.certificateFile.trim();
    tls.keyPath = f.keyFile.trim();
  }

  const ech = buildEch(f);
  if (ech) tls.ech = ech;
  const utls = buildUtls(f);
  if (utls) tls.utls = utls;
  return tls;
}

function transportOptionsFromDraft(f: TransportDraftFields): CreateTransportOptions | undefined {
  if (!f.transportType) return undefined;
  return {
    type: f.transportType,
    path: f.transportPath.trim() || undefined,
    host: f.transportHost.trim() || undefined,
    serviceName: f.transportServiceName.trim() || undefined,
    method: f.transportMethod.trim() || undefined
  };
}

// ---------------------------------------------------------------------------
// Default draft factories.
// ---------------------------------------------------------------------------

function defaultBaseDraft(base: string, existingTags: readonly string[]): InboundBaseDraft {
  return {
    tag: uniqueDefaultTag(base, existingTags),
    listen: "::",
    listenPort: existingTags.length === 0 ? 8443 : randomPort()
  };
}

function defaultTlsDraftFields(enabled: boolean): TlsDraftFields {
  return {
    tlsEnabled: enabled,
    tlsServerName: "",
    tlsAlpn: [],
    tlsMinVersion: "",
    tlsMaxVersion: "",
    tlsCipherSuites: [],
    certMode: "path",
    certificateFile: "",
    keyFile: "",
    certificate: "",
    key: "",
    echEnabled: false,
    echKey: "",
    echPqSignatureSchemesEnabled: false,
    echDynamicRecordSizingDisabled: false,
    acmeEnabled: false,
    acmeDomain: [],
    acmeEmail: "",
    acmeProvider: "",
    acmeDns01Provider: "",
    acmeDns01ApiToken: "",
    acmeDns01AccessKeyId: "",
    acmeDns01AccessKeySecret: "",
    utlsEnabled: false,
    utlsFingerprint: "",
    realityEnabled: false,
    realityHandshakeServer: "",
    realityHandshakePort: "",
    realityPrivateKey: "",
    realityShortId: [],
    realityMaxTimeDifference: ""
  };
}

function defaultTransportDraftFields(): TransportDraftFields {
  return { transportType: "", transportPath: "", transportHost: "", transportServiceName: "", transportMethod: "" };
}

export function createDefaultVlessInboundDraft(existingTags: readonly string[] = []): VlessInboundDraft {
  return { protocol: "vless", ...defaultBaseDraft("vless-in", existingTags), ...defaultTlsDraftFields(true), ...defaultTransportDraftFields() };
}

export function createDefaultVmessInboundDraft(existingTags: readonly string[] = []): VmessInboundDraft {
  return { protocol: "vmess", ...defaultBaseDraft("vmess-in", existingTags), ...defaultTlsDraftFields(true), ...defaultTransportDraftFields() };
}

export function createDefaultTrojanInboundDraft(existingTags: readonly string[] = []): TrojanInboundDraft {
  return { protocol: "trojan", ...defaultBaseDraft("trojan-in", existingTags), ...defaultTlsDraftFields(true), ...defaultTransportDraftFields() };
}

export function createDefaultTuicInboundDraft(existingTags: readonly string[] = []): TuicInboundDraft {
  return { protocol: "tuic", ...defaultBaseDraft("tuic-in", existingTags), ...defaultTlsDraftFields(true), congestionControl: "" };
}

export function createDefaultShadowsocksInboundDraft(existingTags: readonly string[] = []): ShadowsocksInboundDraft {
  return { protocol: "shadowsocks", ...defaultBaseDraft("ss-in", existingTags), method: SHADOWSOCKS_DEFAULT_METHOD, password: "" };
}

export function createDefaultHysteria2InboundDraft(existingTags: readonly string[] = []): HysteriaInboundDraft {
  return {
    protocol: "hysteria2",
    tag: uniqueDefaultTag("Hysteria2", existingTags),
    listen: "::",
    listenPort: existingTags.length === 0 ? 8443 : randomPort(),
    upMbps: "",
    downMbps: "",
    ignoreClientBandwidth: false,
    udpTimeout: "",
    udpFragment: false,
    brutalDebug: false,
    portHoppingRange: "",
    obfsEnabled: false,
    obfsPassword: "",
    masquerade: "",
    masqueradeType: "",
    masqueradeDirectory: "",
    masqueradeRewriteHost: false,
    masqueradeStatusCode: "",
    masqueradeHeaders: "",
    masqueradeContent: "",
    tlsServerName: "",
    tlsAlpn: [],
    tlsMinVersion: "",
    tlsMaxVersion: "",
    tlsCipherSuites: [],
    certMode: "path",
    certificateFile: "",
    keyFile: "",
    certificate: "",
    key: "",
    echEnabled: false,
    echKey: "",
    echPqSignatureSchemesEnabled: false,
    echDynamicRecordSizingDisabled: false,
    acmeEnabled: false,
    acmeDomain: [],
    acmeEmail: "",
    acmeProvider: "",
    acmeDns01Provider: "",
    acmeDns01ApiToken: "",
    acmeDns01AccessKeyId: "",
    acmeDns01AccessKeySecret: ""
  };
}

/** Default draft for a given protocol (used by the "add inbound" / protocol-switch flows). */
export function createDefaultInboundDraft(protocol: SingBoxProtocol, existingTags: readonly string[] = []): SingBoxInboundDraft {
  switch (protocol) {
    case "vless":
      return createDefaultVlessInboundDraft(existingTags);
    case "vmess":
      return createDefaultVmessInboundDraft(existingTags);
    case "trojan":
      return createDefaultTrojanInboundDraft(existingTags);
    case "tuic":
      return createDefaultTuicInboundDraft(existingTags);
    case "shadowsocks":
      return createDefaultShadowsocksInboundDraft(existingTags);
    case "hysteria2":
      return createDefaultHysteria2InboundDraft(existingTags);
  }
}

export function createDefaultSingBoxCoreDraft(): SingBoxCoreDraft {
  return {
    logLevel: "info",
    singboxVersion: "1.12",
    inbounds: [createDefaultHysteria2InboundDraft([])],
    outbounds: [],
    route: {},
    dns: {},
    experimental: {}
  };
}

// ---------------------------------------------------------------------------
// Default factories for the outbounds / route / rule-sets / dns sections.
// These produce WIRE-SHAPED objects the dashboard editors mutate in place.
// ---------------------------------------------------------------------------

function uniqueTag(base: string, existing: readonly string[]): string {
  if (!existing.includes(base)) return base;
  let n = 2;
  while (existing.includes(`${base}-${n}`)) n += 1;
  return `${base}-${n}`;
}

/** Outbound types the sing-box editor can add. `block`/`dns` are legacy (route actions ≥1.11). */
export const SINGBOX_OUTBOUND_TYPES = [
  "direct", "block", "socks", "http", "shadowsocks", "vmess", "vless", "trojan",
  "hysteria2", "tuic", "anytls", "ssh", "dns", "selector", "urltest"
] as const;
export type SingBoxOutboundType = (typeof SINGBOX_OUTBOUND_TYPES)[number];

/** selector/urltest outbounds are the "balancers" of sing-box (member picking). */
export const SINGBOX_BALANCER_OUTBOUND_TYPES: readonly SingBoxOutboundType[] = ["selector", "urltest"];

export function createDefaultSingBoxOutbound(type: SingBoxOutboundType, existingTags: readonly string[] = []): SingBoxOutbound {
  const o: Record<string, JsonValue> = { type, tag: uniqueTag(type, existingTags) };
  switch (type) {
    case "direct":
    case "block":
    case "dns":
      break;
    case "selector":
      o.outbounds = [];
      break;
    case "urltest":
      o.outbounds = [];
      o.url = "https://www.gstatic.com/generate_204";
      o.interval = "3m";
      break;
    case "socks":
    case "http":
      o.server = "";
      o.server_port = 1080;
      break;
    case "shadowsocks":
      o.server = "";
      o.server_port = 443;
      o.method = "aes-128-gcm";
      o.password = "";
      break;
    case "vmess":
      o.server = "";
      o.server_port = 443;
      o.uuid = "";
      o.security = "auto";
      break;
    case "vless":
      o.server = "";
      o.server_port = 443;
      o.uuid = "";
      break;
    case "trojan":
    case "hysteria2":
    case "anytls":
      o.server = "";
      o.server_port = 443;
      o.password = "";
      break;
    case "tuic":
      o.server = "";
      o.server_port = 443;
      o.uuid = "";
      o.password = "";
      break;
    case "ssh":
      o.server = "";
      o.server_port = 22;
      o.user = "";
      o.password = "";
      break;
  }
  return o as SingBoxOutbound;
}

export function createDefaultSingBoxRouteRule(): SingBoxRouteRule {
  // Empty matcher; the editor fills matchers + the action (outbound tag) before it's useful.
  return {};
}

export const SINGBOX_RULE_SET_TYPES = ["remote", "local", "inline"] as const;
export type SingBoxRuleSetType = (typeof SINGBOX_RULE_SET_TYPES)[number];

export function createDefaultSingBoxRuleSet(type: SingBoxRuleSetType, existingTags: readonly string[] = []): SingBoxRuleSet {
  const tag = uniqueTag("rule-set", existingTags);
  if (type === "remote") return { type, tag, format: "binary", url: "", download_detour: "" };
  if (type === "local") return { type, tag, format: "binary", path: "" };
  return { type: "inline", tag, rules: [] };
}

/** DNS server default. 1.12 uses typed servers ({type,server}); 1.11 uses {address}. */
export function createDefaultSingBoxDnsServer(version: SingBoxVersion, existingTags: readonly string[] = []): SingBoxDnsServer {
  const tag = uniqueTag("dns", existingTags);
  return version === "1.12" ? { tag, type: "udp", server: "8.8.8.8" } : { tag, address: "8.8.8.8" };
}

export function createDefaultSingBoxDnsRule(): SingBoxDnsRule {
  return {};
}

// ---------------------------------------------------------------------------
// Hysteria2 masquerade (unchanged behaviour from the original kit).
// ---------------------------------------------------------------------------

/**
 * sing-box requires masquerade to be a full URL with a scheme (e.g. "https://example.com").
 * Users naturally type a bare domain, so default to https:// rather than reject it - this is
 * exactly the failure mode that shipped once already (bare domain -> sing-box "unknown
 * masquerade URL scheme" error, only surfaced at node-start time).
 */
function normalizeMasqueradeUrl(value: string): string | undefined {
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  return /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed) ? trimmed : `https://${trimmed}`;
}

function buildMasquerade(draft: HysteriaInboundDraft): string | JsonObject | undefined {
  switch (draft.masqueradeType) {
    case "file": {
      const directory = draft.masqueradeDirectory.trim();
      return directory ? { type: "file", directory } : undefined;
    }
    case "proxy": {
      const url = normalizeMasqueradeUrl(draft.masquerade);
      if (!url) return undefined;
      const out: JsonObject = { type: "proxy", url };
      return draft.masqueradeRewriteHost ? { ...out, rewrite_host: true } : out;
    }
    case "string": {
      const out: Record<string, JsonValue> = { type: "string" };
      if (draft.masqueradeStatusCode.trim()) out.status_code = Number(draft.masqueradeStatusCode.trim());
      const headers = parseHeaders(draft.masqueradeHeaders);
      if (headers) out.headers = headers;
      if (draft.masqueradeContent) out.content = draft.masqueradeContent;
      return out.status_code === undefined && !out.headers && out.content === undefined ? undefined : out;
    }
    default:
      return normalizeMasqueradeUrl(draft.masquerade);
  }
}

/** Hysteria2 TLS uses the same shared TLS builder plus its always-on cert/acme handling. */
function hysteria2TlsOptions(draft: HysteriaInboundDraft): CreateTlsOptions {
  const alpn = draft.tlsAlpn.map(v => v.trim()).filter(Boolean);
  const cipherSuites = draft.tlsCipherSuites.map(v => v.trim()).filter(Boolean);
  const acme = buildAcme(draft);
  const tls: {
    enabled: boolean;
    serverName?: string;
    alpn?: readonly string[];
    minVersion?: string;
    maxVersion?: string;
    cipherSuites?: readonly string[];
    certificatePath?: string;
    keyPath?: string;
    certificate?: string | readonly string[];
    key?: string | readonly string[];
    ech?: JsonObject;
    acme?: JsonObject;
  } = { enabled: true };
  if (draft.tlsServerName.trim()) tls.serverName = draft.tlsServerName.trim();
  if (alpn.length > 0) tls.alpn = alpn;
  if (draft.tlsMinVersion.trim()) tls.minVersion = draft.tlsMinVersion.trim();
  if (draft.tlsMaxVersion.trim()) tls.maxVersion = draft.tlsMaxVersion.trim();
  if (cipherSuites.length > 0) tls.cipherSuites = cipherSuites;
  if (acme) {
    tls.acme = acme;
  } else if (draft.certMode === "content") {
    tls.certificate = linesToArray(draft.certificate);
    tls.key = linesToArray(draft.key);
  } else {
    tls.certificatePath = draft.certificateFile.trim();
    tls.keyPath = draft.keyFile.trim();
  }
  const ech = buildEch(draft);
  if (ech) tls.ech = ech;
  return tls;
}

// ---------------------------------------------------------------------------
// draft -> Create*InboundOptions, per protocol.
// ---------------------------------------------------------------------------

function baseOptions(draft: InboundBaseDraft & { protocol: string }): { tag: string; listen: string; listenPort: number } {
  const listenPort = parseListenPort(draft.listenPort);
  if (listenPort === undefined) {
    throw new Error(`/listenPort: listen port must be an integer between 1 and 65535 (tag: ${draft.tag || "?"}).`);
  }
  return { tag: draft.tag.trim(), listen: draft.listen.trim() || "::", listenPort };
}

export function inboundOptionsFromDraft(draft: SingBoxInboundDraft): CreateInboundOptions {
  switch (draft.protocol) {
    case "vless":
      return { protocol: "vless", ...baseOptions(draft), tls: tlsOptionsFromDraft(draft), transport: transportOptionsFromDraft(draft) };
    case "vmess":
      return { protocol: "vmess", ...baseOptions(draft), tls: tlsOptionsFromDraft(draft), transport: transportOptionsFromDraft(draft) };
    case "trojan":
      return { protocol: "trojan", ...baseOptions(draft), tls: tlsOptionsFromDraft(draft), transport: transportOptionsFromDraft(draft) };
    case "tuic":
      return { protocol: "tuic", ...baseOptions(draft), tls: tlsOptionsFromDraft({ ...draft, tlsEnabled: true }), congestionControl: draft.congestionControl.trim() || undefined };
    case "shadowsocks":
      return { protocol: "shadowsocks", ...baseOptions(draft), method: draft.method.trim(), password: draft.password.trim() || undefined };
    case "hysteria2":
      return {
        protocol: "hysteria2",
        ...baseOptions(draft),
        upMbps: draft.upMbps.trim() ? Number(draft.upMbps.trim()) : undefined,
        downMbps: draft.downMbps.trim() ? Number(draft.downMbps.trim()) : undefined,
        ignoreClientBandwidth: draft.ignoreClientBandwidth || undefined,
        udpTimeout: draft.udpTimeout.trim() || undefined,
        udpFragment: draft.udpFragment || undefined,
        brutalDebug: draft.brutalDebug || undefined,
        portHoppingRange: draft.portHoppingRange.trim() || undefined,
        obfs: draft.obfsEnabled ? { password: draft.obfsPassword.trim() } : undefined,
        masquerade: buildMasquerade(draft),
        tls: hysteria2TlsOptions(draft)
      };
  }
}

// ---------------------------------------------------------------------------
// Draft-level validation (mirrors validation.ts, at the pre-serialization stage).
// ---------------------------------------------------------------------------

function validateBaseDraft(draft: SingBoxInboundDraft, index: number, allTags: readonly string[]): SingBoxValidationIssue[] {
  const issues: SingBoxValidationIssue[] = [];
  const base = `/inbounds/${index}`;
  const tag = draft.tag.trim();
  if (!tag) {
    issues.push(issue(`${base}/tag`, "SB_FORM_TAG_REQUIRED", "Tag is required."));
  } else if (allTags.filter(t => t.trim() === tag).length > 1) {
    issues.push(issue(`${base}/tag`, "SB_FORM_TAG_DUPLICATE", `Duplicate inbound tag: ${tag}.`));
  }
  const listenPort = parseListenPort(draft.listenPort);
  if (listenPort === undefined || listenPort < 1 || listenPort > 65535) {
    issues.push(issue(`${base}/listenPort`, "SB_FORM_LISTEN_PORT_INVALID", "Listen port must be an integer between 1 and 65535."));
  }
  return issues;
}

function validateTlsDraft(f: TlsDraftFields, base: string): SingBoxValidationIssue[] {
  const issues: SingBoxValidationIssue[] = [];
  if (!f.tlsEnabled) return issues;
  if (f.realityEnabled) {
    if (!f.realityHandshakeServer.trim()) {
      issues.push(issue(`${base}/realityHandshakeServer`, "SB_FORM_REALITY_HANDSHAKE_REQUIRED", "REALITY requires a handshake server."));
    }
    if (!f.realityPrivateKey.trim()) {
      issues.push(issue(`${base}/realityPrivateKey`, "SB_FORM_REALITY_KEY_REQUIRED", "REALITY requires a private key."));
    }
  } else if (f.acmeEnabled) {
    if (f.acmeDomain.map(d => d.trim()).filter(Boolean).length === 0) {
      issues.push(issue(`${base}/acmeDomain`, "SB_FORM_ACME_DOMAIN_REQUIRED", "At least one domain is required for ACME."));
    }
    if (f.acmeDns01Provider === "cloudflare" && !f.acmeDns01ApiToken.trim()) {
      issues.push(issue(`${base}/acmeDns01ApiToken`, "SB_FORM_ACME_CF_TOKEN_REQUIRED", "A Cloudflare API token is required for the Cloudflare DNS-01 challenge."));
    }
  }
  return issues;
}

export function validateInboundDraft(draft: SingBoxInboundDraft, index: number, allTags: readonly string[]): SingBoxValidationIssue[] {
  const issues = validateBaseDraft(draft, index, allTags);
  const base = `/inbounds/${index}`;
  switch (draft.protocol) {
    case "vless":
    case "vmess":
    case "trojan":
      issues.push(...validateTlsDraft(draft, base));
      break;
    case "tuic":
      issues.push(...validateTlsDraft({ ...draft, tlsEnabled: true }, base));
      break;
    case "shadowsocks":
      if (!draft.method.trim()) {
        issues.push(issue(`${base}/method`, "SB_FORM_SS_METHOD_REQUIRED", "Shadowsocks requires an encryption method."));
      }
      break;
    case "hysteria2":
      issues.push(...validateHysteria2InboundDraft(draft, index, allTags).filter(i => !i.path.endsWith("/tag") && !i.path.endsWith("/listenPort")));
      break;
  }
  return issues;
}

/** Mirrors the validation.ts semantic rules for hysteria2, at the draft/form level. */
export function validateHysteria2InboundDraft(draft: HysteriaInboundDraft, index: number, allTags: readonly string[]): SingBoxValidationIssue[] {
  const issues = validateBaseDraft(draft, index, allTags);
  const base = `/inbounds/${index}`;

  if (draft.upMbps.trim() && !/^\d+$/.test(draft.upMbps.trim())) {
    issues.push(issue(`${base}/upMbps`, "SB_FORM_UP_MBPS_INVALID", "Up mbps must be a non-negative integer."));
  }
  if (draft.downMbps.trim() && !/^\d+$/.test(draft.downMbps.trim())) {
    issues.push(issue(`${base}/downMbps`, "SB_FORM_DOWN_MBPS_INVALID", "Down mbps must be a non-negative integer."));
  }
  if (draft.obfsEnabled && !draft.obfsPassword.trim()) {
    issues.push(issue(`${base}/obfsPassword`, "SB_FORM_OBFS_PASSWORD_REQUIRED", "Obfuscation password is required when obfuscation is enabled."));
  }
  if (draft.udpTimeout.trim() && !/^\d+(ns|us|µs|ms|s|m|h)?$/.test(draft.udpTimeout.trim())) {
    issues.push(issue(`${base}/udpTimeout`, "SB_FORM_UDP_TIMEOUT_INVALID", "UDP timeout must be a duration such as 30s, 5m, or a bare number of seconds."));
  }
  if (draft.portHoppingRange.trim() && !/^[\d,\-\s]+$/.test(draft.portHoppingRange.trim())) {
    issues.push(issue(`${base}/portHoppingRange`, "SB_FORM_PORT_HOPPING_INVALID", "Port hopping range must be ports/ranges, e.g. 20000-50000 or 443,8443."));
  }
  if (draft.masqueradeType === "file" && !draft.masqueradeDirectory.trim()) {
    issues.push(issue(`${base}/masqueradeDirectory`, "SB_FORM_MASQUERADE_DIRECTORY_REQUIRED", "A directory is required for a file masquerade."));
  }
  if (draft.masqueradeType === "proxy" && !draft.masquerade.trim()) {
    issues.push(issue(`${base}/masquerade`, "SB_FORM_MASQUERADE_URL_REQUIRED", "A URL is required for a proxy masquerade."));
  }
  if (draft.masqueradeType === "string") {
    if (draft.masqueradeStatusCode.trim() && !/^\d+$/.test(draft.masqueradeStatusCode.trim())) {
      issues.push(issue(`${base}/masqueradeStatusCode`, "SB_FORM_MASQUERADE_STATUS_INVALID", "Status code must be an integer."));
    }
    if (draft.masqueradeHeaders.trim() && !isJsonObject(draft.masqueradeHeaders)) {
      issues.push(issue(`${base}/masqueradeHeaders`, "SB_FORM_MASQUERADE_HEADERS_INVALID", "Headers must be a JSON object, e.g. {\"X-Key\": \"value\"}."));
    }
  }
  if (draft.acmeEnabled) {
    if (draft.acmeDomain.map(d => d.trim()).filter(Boolean).length === 0) {
      issues.push(issue(`${base}/acmeDomain`, "SB_FORM_ACME_DOMAIN_REQUIRED", "At least one domain is required for ACME."));
    }
    if (draft.acmeDns01Provider === "cloudflare" && !draft.acmeDns01ApiToken.trim()) {
      issues.push(issue(`${base}/acmeDns01ApiToken`, "SB_FORM_ACME_CF_TOKEN_REQUIRED", "A Cloudflare API token is required for the Cloudflare DNS-01 challenge."));
    }
    if (draft.acmeDns01Provider === "alidns" && (!draft.acmeDns01AccessKeyId.trim() || !draft.acmeDns01AccessKeySecret.trim())) {
      issues.push(issue(`${base}/acmeDns01AccessKeyId`, "SB_FORM_ACME_ALIDNS_KEYS_REQUIRED", "AliDNS access key id and secret are required for the AliDNS DNS-01 challenge."));
    }
  }
  return issues;
}

export function validateSingBoxCoreDraft(draft: SingBoxCoreDraft): SingBoxValidationIssue[] {
  const issues: SingBoxValidationIssue[] = [];
  if (draft.inbounds.length === 0) {
    issues.push(issue("/inbounds", "SB_FORM_NO_INBOUNDS", "At least one inbound is required."));
  }
  const allTags = draft.inbounds.map(i => i.tag);
  draft.inbounds.forEach((inbound, index) => {
    issues.push(...validateInboundDraft(inbound, index, allTags));
  });
  return issues;
}

export function createSingBoxCoreConfigFromDraft(draft: SingBoxCoreDraft): SingBoxCoreConfig {
  const issues = validateSingBoxCoreDraft(draft);
  if (issues.length > 0) {
    const firstIssue = issues[0]!;
    throw new Error(`${firstIssue.path}: ${firstIssue.message}`);
  }
  return createSingBoxCoreConfig({
    logLevel: draft.logLevel,
    singboxVersion: draft.singboxVersion,
    inbounds: draft.inbounds.map(inboundOptionsFromDraft),
    outbounds: draft.outbounds,
    route: draft.route,
    dns: draft.dns,
    experimental: draft.experimental
  });
}

export function generateSingBoxCoreConfigJsonFromDraft(draft: SingBoxCoreDraft, space = 2): string {
  return JSON.stringify(createSingBoxCoreConfigFromDraft(draft), null, space);
}

/** Exposed for callers that build a single inbound's config JSON without a full draft (e.g. previews). */
export function createInboundConfigFromDraft(draft: SingBoxInboundDraft) {
  return createInboundConfig(inboundOptionsFromDraft(draft));
}

/** Back-compat alias for the original single-protocol export name. */
export function createHysteria2InboundConfigFromDraft(draft: HysteriaInboundDraft) {
  return createHysteria2InboundConfig(inboundOptionsFromDraft(draft) as Parameters<typeof createHysteria2InboundConfig>[0]);
}
