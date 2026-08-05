import { assertValidSingBoxCoreConfig } from "./validation.js";
export function createHysteria2InboundConfig(options) {
    const tls = { enabled: true };
    if (options.tls.serverName)
        tls.server_name = options.tls.serverName;
    if (options.tls.alpn && options.tls.alpn.length > 0)
        tls.alpn = [...options.tls.alpn];
    // Path-mode fields are emitted whenever present (even ""), mirroring the Xray inbound TLS
    // certificate path/content toggle, which always writes both keys once that mode is chosen.
    if (options.tls.certificatePath !== undefined)
        tls.certificate_path = options.tls.certificatePath;
    if (options.tls.keyPath !== undefined)
        tls.key_path = options.tls.keyPath;
    if (options.tls.certificate !== undefined) {
        tls.certificate = (typeof options.tls.certificate === "string" ? options.tls.certificate : [...options.tls.certificate]);
    }
    if (options.tls.key !== undefined) {
        tls.key = (typeof options.tls.key === "string" ? options.tls.key : [...options.tls.key]);
    }
    const inbound = {
        type: "hysteria2",
        tag: options.tag,
        listen: options.listen ?? "::",
        listen_port: options.listenPort,
        // The panel injects real users into the running node config at sync time; this kit
        // never represents or edits users, so it is always emitted empty here.
        users: [],
        tls: tls
    };
    if (options.upMbps !== undefined)
        inbound.up_mbps = options.upMbps;
    if (options.downMbps !== undefined)
        inbound.down_mbps = options.downMbps;
    if (options.ignoreClientBandwidth !== undefined)
        inbound.ignore_client_bandwidth = options.ignoreClientBandwidth;
    if (options.obfs) {
        inbound.obfs = { type: "salamander", password: options.obfs.password };
    }
    if (options.masquerade)
        inbound.masquerade = options.masquerade;
    return inbound;
}
function configFromOptions(options) {
    return {
        log: { level: options.logLevel ?? "info" },
        inbounds: options.inbounds.map(createHysteria2InboundConfig),
        outbounds: [{ type: "direct" }]
    };
}
export function createSingBoxCoreConfig(options) {
    return assertValidSingBoxCoreConfig(configFromOptions(options));
}
export function generateSingBoxCoreConfigJson(options, space = 2) {
    return JSON.stringify(createSingBoxCoreConfig(options), null, space);
}
export function createSingBoxCorePayload(options) {
    const { name = "singbox_core", ...configOptions } = options;
    return {
        name,
        type: "singbox",
        config: createSingBoxCoreConfig(configOptions),
        exclude_inbound_tags: [],
        fallbacks_inbound_tags: []
    };
}
//# sourceMappingURL=core.js.map