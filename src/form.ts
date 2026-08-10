import { createHysteria2InboundConfig, createSingBoxCoreConfig } from "./core.js";
import type { JsonObject, JsonValue, SingBoxCoreConfig, SingBoxValidationIssue } from "./types.js";

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
  // Masquerade: `masquerade` is the bare-URL shorthand (type "") and the proxy URL (type "proxy").
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
  // ECH (modeled for parity with the Xray inbound TLS editor; off by default).
  readonly echEnabled: boolean;
  readonly echKey: string;
  readonly echPqSignatureSchemesEnabled: boolean;
  readonly echDynamicRecordSizingDisabled: boolean;
  // ACME auto-cert (mutually exclusive with the certificate/key above; off by default).
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

function uniqueDefaultTag(existingTags: readonly string[]): string {
  const taken = new Set(existingTags.map(t => t.trim()));
  if (!taken.has("Hysteria2")) return "Hysteria2";
  let n = 2;
  while (taken.has(`Hysteria2_${n}`)) n += 1;
  return `Hysteria2_${n}`;
}

export function createDefaultHysteria2InboundDraft(existingTags: readonly string[] = []): HysteriaInboundDraft {
  return {
    tag: uniqueDefaultTag(existingTags),
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

export function createDefaultSingBoxCoreDraft(): SingBoxCoreDraft {
  return {
    logLevel: "info",
    inbounds: [createDefaultHysteria2InboundDraft([])]
  };
}

/** Mirrors the validation.ts semantic rules, at the draft/form level (pre-serialization). */
export function validateHysteria2InboundDraft(draft: HysteriaInboundDraft, index: number, allTags: readonly string[]): SingBoxValidationIssue[] {
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
    issues.push(...validateHysteria2InboundDraft(inbound, index, allTags));
  });

  return issues;
}

/**
 * sing-box requires masquerade to be a full URL with a scheme (e.g. \"https://example.com\").
 * Users naturally type a bare domain here, so default to https:// rather than reject it -
 * this is exactly the failure mode that shipped once already (bare domain -> sing-box
 * \"unknown masquerade URL scheme\" error, only surfaced at node-start time).
 */
function normalizeMasqueradeUrl(value: string): string | undefined {
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  return /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed) ? trimmed : `https://${trimmed}`;
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

function linesToArray(text: string): string[] {
  return text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
}

/** Builds the masquerade value (bare-URL string shorthand, or the long-form object). */
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
      // "" -> bare-URL shorthand (the historical behavior).
      return normalizeMasqueradeUrl(draft.masquerade);
  }
}

/** Builds the tls.ech object, or undefined when ECH is off. */
function buildEch(draft: HysteriaInboundDraft): JsonObject | undefined {
  if (!draft.echEnabled) return undefined;
  const ech: Record<string, JsonValue> = { enabled: true };
  const key = linesToArray(draft.echKey);
  if (key.length > 0) ech.key = key;
  if (draft.echPqSignatureSchemesEnabled) ech.pq_signature_schemes_enabled = true;
  if (draft.echDynamicRecordSizingDisabled) ech.dynamic_record_sizing_disabled = true;
  return ech;
}

/** Builds the tls.acme object, or undefined when ACME is off. */
function buildAcme(draft: HysteriaInboundDraft): JsonObject | undefined {
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

function hysteria2InboundOptionsFromDraft(draft: HysteriaInboundDraft) {
  const listenPort = parseListenPort(draft.listenPort);
  if (listenPort === undefined) {
    throw new Error(`/listenPort: listen port must be an integer between 1 and 65535 (tag: ${draft.tag || "?"}).`);
  }

  const upMbps = draft.upMbps.trim() ? Number(draft.upMbps.trim()) : undefined;
  const downMbps = draft.downMbps.trim() ? Number(draft.downMbps.trim()) : undefined;
  const alpn = draft.tlsAlpn.map(v => v.trim()).filter(Boolean);
  const cipherSuites = draft.tlsCipherSuites.map(v => v.trim()).filter(Boolean);
  const acme = buildAcme(draft);

  const tls: {
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
  } = {};
  if (draft.tlsServerName.trim()) tls.serverName = draft.tlsServerName.trim();
  if (alpn.length > 0) tls.alpn = alpn;
  if (draft.tlsMinVersion.trim()) tls.minVersion = draft.tlsMinVersion.trim();
  if (draft.tlsMaxVersion.trim()) tls.maxVersion = draft.tlsMaxVersion.trim();
  if (cipherSuites.length > 0) tls.cipherSuites = cipherSuites;

  // ACME and an explicit certificate are mutually exclusive; sing-box rejects both at once.
  // When ACME is on it owns the certificate, so the manual cert fields are not emitted.
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

  return {
    tag: draft.tag.trim(),
    listen: draft.listen.trim() || "::",
    listenPort,
    upMbps,
    downMbps,
    ignoreClientBandwidth: draft.ignoreClientBandwidth || undefined,
    udpTimeout: draft.udpTimeout.trim() || undefined,
    udpFragment: draft.udpFragment || undefined,
    brutalDebug: draft.brutalDebug || undefined,
    portHoppingRange: draft.portHoppingRange.trim() || undefined,
    obfs: draft.obfsEnabled ? { password: draft.obfsPassword.trim() } : undefined,
    masquerade: buildMasquerade(draft),
    tls
  };
}

export function createSingBoxCoreConfigFromDraft(draft: SingBoxCoreDraft): SingBoxCoreConfig {
  const issues = validateSingBoxCoreDraft(draft);
  if (issues.length > 0) {
    const firstIssue = issues[0]!;
    throw new Error(`${firstIssue.path}: ${firstIssue.message}`);
  }
  return createSingBoxCoreConfig({
    logLevel: draft.logLevel,
    inbounds: draft.inbounds.map(hysteria2InboundOptionsFromDraft)
  });
}

export function generateSingBoxCoreConfigJsonFromDraft(draft: SingBoxCoreDraft, space = 2): string {
  return JSON.stringify(createSingBoxCoreConfigFromDraft(draft), null, space);
}

/** Exposed for callers that build a single inbound's config JSON without a full draft (e.g. previews). */
export function createHysteria2InboundConfigFromDraft(draft: HysteriaInboundDraft) {
  return createHysteria2InboundConfig(hysteria2InboundOptionsFromDraft(draft));
}
