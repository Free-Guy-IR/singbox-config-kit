import { createHysteria2InboundConfig, createSingBoxCoreConfig } from "./core.js";
import type { SingBoxCoreConfig, SingBoxValidationIssue } from "./types.js";

export type SingBoxCertMode = "path" | "content";

/**
 * Form-state shape for a single Hysteria2 inbound, distinct from the persisted JSON shape.
 * `certMode` is UI-only: it decides whether `certificateFile`/`keyFile` (-> certificate_path/
 * key_path) or `certificate`/`key` (-> inline PEM content) are serialized on save, mirroring
 * the existing Xray inbound TLS certificate path/content toggle.
 */
export type HysteriaInboundDraft = {
  readonly tag: string;
  readonly listen: string;
  readonly listenPort: number | string;
  readonly upMbps: string;
  readonly downMbps: string;
  readonly ignoreClientBandwidth: boolean;
  readonly obfsEnabled: boolean;
  readonly obfsPassword: string;
  readonly masquerade: string;
  readonly tlsServerName: string;
  readonly tlsAlpn: readonly string[];
  readonly certMode: SingBoxCertMode;
  readonly certificateFile: string;
  readonly keyFile: string;
  readonly certificate: string;
  readonly key: string;
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
    obfsEnabled: false,
    obfsPassword: "",
    masquerade: "",
    tlsServerName: "",
    tlsAlpn: [],
    certMode: "path",
    certificateFile: "",
    keyFile: "",
    certificate: "",
    key: ""
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

function hysteria2InboundOptionsFromDraft(draft: HysteriaInboundDraft) {
  const listenPort = parseListenPort(draft.listenPort);
  if (listenPort === undefined) {
    throw new Error(`/listenPort: listen port must be an integer between 1 and 65535 (tag: ${draft.tag || "?"}).`);
  }

  const upMbps = draft.upMbps.trim() ? Number(draft.upMbps.trim()) : undefined;
  const downMbps = draft.downMbps.trim() ? Number(draft.downMbps.trim()) : undefined;
  const alpn = draft.tlsAlpn.map(v => v.trim()).filter(Boolean);

  const tls: {
    serverName?: string;
    alpn?: readonly string[];
    certificatePath?: string;
    keyPath?: string;
    certificate?: string | readonly string[];
    key?: string | readonly string[];
  } = {};
  if (draft.tlsServerName.trim()) tls.serverName = draft.tlsServerName.trim();
  if (alpn.length > 0) tls.alpn = alpn;

  if (draft.certMode === "content") {
    tls.certificate = draft.certificate
      .split(/\r?\n/)
      .map(line => line.trim())
      .filter(Boolean);
    tls.key = draft.key
      .split(/\r?\n/)
      .map(line => line.trim())
      .filter(Boolean);
  } else {
    tls.certificatePath = draft.certificateFile.trim();
    tls.keyPath = draft.keyFile.trim();
  }

  return {
    tag: draft.tag.trim(),
    listen: draft.listen.trim() || "::",
    listenPort,
    upMbps,
    downMbps,
    ignoreClientBandwidth: draft.ignoreClientBandwidth || undefined,
    obfs: draft.obfsEnabled ? { password: draft.obfsPassword.trim() } : undefined,
    masquerade: normalizeMasqueradeUrl(draft.masquerade),
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
