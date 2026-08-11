import { createHysteria2InboundConfig, createInboundConfig, createSingBoxCoreConfig } from "./core.js";
function issue(path, code, message) {
    return { path, code, message };
}
function parseListenPort(value) {
    if (typeof value === "number")
        return Number.isInteger(value) ? value : undefined;
    const trimmed = value.trim();
    if (!/^\d+$/.test(trimmed))
        return undefined;
    return Number(trimmed);
}
function randomPort() {
    return Math.floor(Math.random() * (65535 - 10000 + 1)) + 10000;
}
function uniqueDefaultTag(base, existingTags) {
    const taken = new Set(existingTags.map(t => t.trim()));
    if (!taken.has(base))
        return base;
    let n = 2;
    while (taken.has(`${base}_${n}`))
        n += 1;
    return `${base}_${n}`;
}
const SHADOWSOCKS_DEFAULT_METHOD = "2022-blake3-aes-128-gcm";
// ---------------------------------------------------------------------------
// Shared draft helpers (structural over the field groups above).
// ---------------------------------------------------------------------------
function linesToArray(text) {
    return text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
}
/** True when `text` parses to a plain JSON object (used for masquerade string headers). */
function isJsonObject(text) {
    try {
        const parsed = JSON.parse(text);
        return !!parsed && typeof parsed === "object" && !Array.isArray(parsed);
    }
    catch {
        return false;
    }
}
function parseHeaders(text) {
    const trimmed = text.trim();
    if (!trimmed || !isJsonObject(trimmed))
        return undefined;
    return JSON.parse(trimmed);
}
/** Builds the tls.ech object, or undefined when ECH is off. */
function buildEch(draft) {
    if (!draft.echEnabled)
        return undefined;
    const ech = { enabled: true };
    const key = linesToArray(draft.echKey);
    if (key.length > 0)
        ech.key = key;
    if (draft.echPqSignatureSchemesEnabled)
        ech.pq_signature_schemes_enabled = true;
    if (draft.echDynamicRecordSizingDisabled)
        ech.dynamic_record_sizing_disabled = true;
    return ech;
}
/** Builds the tls.acme object, or undefined when ACME is off. */
function buildAcme(draft) {
    if (!draft.acmeEnabled)
        return undefined;
    const acme = {};
    const domains = draft.acmeDomain.map(d => d.trim()).filter(Boolean);
    if (domains.length > 0)
        acme.domain = domains;
    if (draft.acmeEmail.trim())
        acme.email = draft.acmeEmail.trim();
    if (draft.acmeProvider.trim())
        acme.provider = draft.acmeProvider.trim();
    if (draft.acmeDns01Provider === "cloudflare" && draft.acmeDns01ApiToken.trim()) {
        acme.dns01_challenge = { provider: "cloudflare", api_token: draft.acmeDns01ApiToken.trim() };
    }
    else if (draft.acmeDns01Provider === "alidns" && draft.acmeDns01AccessKeyId.trim()) {
        acme.dns01_challenge = {
            provider: "alidns",
            access_key_id: draft.acmeDns01AccessKeyId.trim(),
            access_key_secret: draft.acmeDns01AccessKeySecret.trim()
        };
    }
    return acme;
}
/** Builds the tls.utls object, or undefined when uTLS is off. */
function buildUtls(f) {
    if (!f.utlsEnabled)
        return undefined;
    const utls = { enabled: true };
    if (f.utlsFingerprint.trim())
        utls.fingerprint = f.utlsFingerprint.trim();
    return utls;
}
/** Builds the tls.reality object, or undefined when REALITY is off. */
function buildReality(f) {
    if (!f.realityEnabled)
        return undefined;
    const reality = {
        enabled: true,
        handshake: {
            server: f.realityHandshakeServer.trim(),
            server_port: f.realityHandshakePort.trim() ? Number(f.realityHandshakePort.trim()) : 443
        },
        private_key: f.realityPrivateKey.trim()
    };
    const shortIds = f.realityShortId.map(s => s.trim()).filter(Boolean);
    if (shortIds.length > 0)
        reality.short_id = shortIds;
    if (f.realityMaxTimeDifference.trim())
        reality.max_time_difference = f.realityMaxTimeDifference.trim();
    return reality;
}
/** Converts the shared TLS draft fields into the camelCase CreateTlsOptions the builders take. */
function tlsOptionsFromDraft(f) {
    if (!f.tlsEnabled)
        return { enabled: false };
    const alpn = f.tlsAlpn.map(v => v.trim()).filter(Boolean);
    const cipherSuites = f.tlsCipherSuites.map(v => v.trim()).filter(Boolean);
    const tls = { enabled: true };
    if (f.tlsServerName.trim())
        tls.serverName = f.tlsServerName.trim();
    if (alpn.length > 0)
        tls.alpn = alpn;
    if (f.tlsMinVersion.trim())
        tls.minVersion = f.tlsMinVersion.trim();
    if (f.tlsMaxVersion.trim())
        tls.maxVersion = f.tlsMaxVersion.trim();
    if (cipherSuites.length > 0)
        tls.cipherSuites = cipherSuites;
    const reality = buildReality(f);
    const acme = buildAcme(f);
    // REALITY, ACME and an explicit certificate are mutually exclusive; sing-box rejects a mix.
    if (reality) {
        tls.reality = reality;
    }
    else if (acme) {
        tls.acme = acme;
    }
    else if (f.certMode === "content") {
        tls.certificate = linesToArray(f.certificate);
        tls.key = linesToArray(f.key);
    }
    else {
        tls.certificatePath = f.certificateFile.trim();
        tls.keyPath = f.keyFile.trim();
    }
    const ech = buildEch(f);
    if (ech)
        tls.ech = ech;
    const utls = buildUtls(f);
    if (utls)
        tls.utls = utls;
    return tls;
}
function transportOptionsFromDraft(f) {
    if (!f.transportType)
        return undefined;
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
function defaultBaseDraft(base, existingTags) {
    return {
        tag: uniqueDefaultTag(base, existingTags),
        listen: "::",
        listenPort: existingTags.length === 0 ? 8443 : randomPort()
    };
}
function defaultTlsDraftFields(enabled) {
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
function defaultTransportDraftFields() {
    return { transportType: "", transportPath: "", transportHost: "", transportServiceName: "", transportMethod: "" };
}
export function createDefaultVlessInboundDraft(existingTags = []) {
    return { protocol: "vless", ...defaultBaseDraft("vless-in", existingTags), ...defaultTlsDraftFields(true), ...defaultTransportDraftFields() };
}
export function createDefaultVmessInboundDraft(existingTags = []) {
    return { protocol: "vmess", ...defaultBaseDraft("vmess-in", existingTags), ...defaultTlsDraftFields(true), ...defaultTransportDraftFields() };
}
export function createDefaultTrojanInboundDraft(existingTags = []) {
    return { protocol: "trojan", ...defaultBaseDraft("trojan-in", existingTags), ...defaultTlsDraftFields(true), ...defaultTransportDraftFields() };
}
export function createDefaultTuicInboundDraft(existingTags = []) {
    return { protocol: "tuic", ...defaultBaseDraft("tuic-in", existingTags), ...defaultTlsDraftFields(true), congestionControl: "" };
}
export function createDefaultShadowsocksInboundDraft(existingTags = []) {
    return { protocol: "shadowsocks", ...defaultBaseDraft("ss-in", existingTags), method: SHADOWSOCKS_DEFAULT_METHOD, password: "" };
}
export function createDefaultHysteria2InboundDraft(existingTags = []) {
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
export function createDefaultInboundDraft(protocol, existingTags = []) {
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
export function createDefaultSingBoxCoreDraft() {
    return { logLevel: "info", inbounds: [createDefaultHysteria2InboundDraft([])] };
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
function normalizeMasqueradeUrl(value) {
    const trimmed = value.trim();
    if (!trimmed)
        return undefined;
    return /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed) ? trimmed : `https://${trimmed}`;
}
function buildMasquerade(draft) {
    switch (draft.masqueradeType) {
        case "file": {
            const directory = draft.masqueradeDirectory.trim();
            return directory ? { type: "file", directory } : undefined;
        }
        case "proxy": {
            const url = normalizeMasqueradeUrl(draft.masquerade);
            if (!url)
                return undefined;
            const out = { type: "proxy", url };
            return draft.masqueradeRewriteHost ? { ...out, rewrite_host: true } : out;
        }
        case "string": {
            const out = { type: "string" };
            if (draft.masqueradeStatusCode.trim())
                out.status_code = Number(draft.masqueradeStatusCode.trim());
            const headers = parseHeaders(draft.masqueradeHeaders);
            if (headers)
                out.headers = headers;
            if (draft.masqueradeContent)
                out.content = draft.masqueradeContent;
            return out.status_code === undefined && !out.headers && out.content === undefined ? undefined : out;
        }
        default:
            return normalizeMasqueradeUrl(draft.masquerade);
    }
}
/** Hysteria2 TLS uses the same shared TLS builder plus its always-on cert/acme handling. */
function hysteria2TlsOptions(draft) {
    const alpn = draft.tlsAlpn.map(v => v.trim()).filter(Boolean);
    const cipherSuites = draft.tlsCipherSuites.map(v => v.trim()).filter(Boolean);
    const acme = buildAcme(draft);
    const tls = { enabled: true };
    if (draft.tlsServerName.trim())
        tls.serverName = draft.tlsServerName.trim();
    if (alpn.length > 0)
        tls.alpn = alpn;
    if (draft.tlsMinVersion.trim())
        tls.minVersion = draft.tlsMinVersion.trim();
    if (draft.tlsMaxVersion.trim())
        tls.maxVersion = draft.tlsMaxVersion.trim();
    if (cipherSuites.length > 0)
        tls.cipherSuites = cipherSuites;
    if (acme) {
        tls.acme = acme;
    }
    else if (draft.certMode === "content") {
        tls.certificate = linesToArray(draft.certificate);
        tls.key = linesToArray(draft.key);
    }
    else {
        tls.certificatePath = draft.certificateFile.trim();
        tls.keyPath = draft.keyFile.trim();
    }
    const ech = buildEch(draft);
    if (ech)
        tls.ech = ech;
    return tls;
}
// ---------------------------------------------------------------------------
// draft -> Create*InboundOptions, per protocol.
// ---------------------------------------------------------------------------
function baseOptions(draft) {
    const listenPort = parseListenPort(draft.listenPort);
    if (listenPort === undefined) {
        throw new Error(`/listenPort: listen port must be an integer between 1 and 65535 (tag: ${draft.tag || "?"}).`);
    }
    return { tag: draft.tag.trim(), listen: draft.listen.trim() || "::", listenPort };
}
export function inboundOptionsFromDraft(draft) {
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
function validateBaseDraft(draft, index, allTags) {
    const issues = [];
    const base = `/inbounds/${index}`;
    const tag = draft.tag.trim();
    if (!tag) {
        issues.push(issue(`${base}/tag`, "SB_FORM_TAG_REQUIRED", "Tag is required."));
    }
    else if (allTags.filter(t => t.trim() === tag).length > 1) {
        issues.push(issue(`${base}/tag`, "SB_FORM_TAG_DUPLICATE", `Duplicate inbound tag: ${tag}.`));
    }
    const listenPort = parseListenPort(draft.listenPort);
    if (listenPort === undefined || listenPort < 1 || listenPort > 65535) {
        issues.push(issue(`${base}/listenPort`, "SB_FORM_LISTEN_PORT_INVALID", "Listen port must be an integer between 1 and 65535."));
    }
    return issues;
}
function validateTlsDraft(f, base) {
    const issues = [];
    if (!f.tlsEnabled)
        return issues;
    if (f.realityEnabled) {
        if (!f.realityHandshakeServer.trim()) {
            issues.push(issue(`${base}/realityHandshakeServer`, "SB_FORM_REALITY_HANDSHAKE_REQUIRED", "REALITY requires a handshake server."));
        }
        if (!f.realityPrivateKey.trim()) {
            issues.push(issue(`${base}/realityPrivateKey`, "SB_FORM_REALITY_KEY_REQUIRED", "REALITY requires a private key."));
        }
    }
    else if (f.acmeEnabled) {
        if (f.acmeDomain.map(d => d.trim()).filter(Boolean).length === 0) {
            issues.push(issue(`${base}/acmeDomain`, "SB_FORM_ACME_DOMAIN_REQUIRED", "At least one domain is required for ACME."));
        }
        if (f.acmeDns01Provider === "cloudflare" && !f.acmeDns01ApiToken.trim()) {
            issues.push(issue(`${base}/acmeDns01ApiToken`, "SB_FORM_ACME_CF_TOKEN_REQUIRED", "A Cloudflare API token is required for the Cloudflare DNS-01 challenge."));
        }
    }
    return issues;
}
export function validateInboundDraft(draft, index, allTags) {
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
export function validateHysteria2InboundDraft(draft, index, allTags) {
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
export function validateSingBoxCoreDraft(draft) {
    const issues = [];
    if (draft.inbounds.length === 0) {
        issues.push(issue("/inbounds", "SB_FORM_NO_INBOUNDS", "At least one inbound is required."));
    }
    const allTags = draft.inbounds.map(i => i.tag);
    draft.inbounds.forEach((inbound, index) => {
        issues.push(...validateInboundDraft(inbound, index, allTags));
    });
    return issues;
}
export function createSingBoxCoreConfigFromDraft(draft) {
    const issues = validateSingBoxCoreDraft(draft);
    if (issues.length > 0) {
        const firstIssue = issues[0];
        throw new Error(`${firstIssue.path}: ${firstIssue.message}`);
    }
    return createSingBoxCoreConfig({
        logLevel: draft.logLevel,
        inbounds: draft.inbounds.map(inboundOptionsFromDraft)
    });
}
export function generateSingBoxCoreConfigJsonFromDraft(draft, space = 2) {
    return JSON.stringify(createSingBoxCoreConfigFromDraft(draft), null, space);
}
/** Exposed for callers that build a single inbound's config JSON without a full draft (e.g. previews). */
export function createInboundConfigFromDraft(draft) {
    return createInboundConfig(inboundOptionsFromDraft(draft));
}
/** Back-compat alias for the original single-protocol export name. */
export function createHysteria2InboundConfigFromDraft(draft) {
    return createHysteria2InboundConfig(inboundOptionsFromDraft(draft));
}
//# sourceMappingURL=form.js.map