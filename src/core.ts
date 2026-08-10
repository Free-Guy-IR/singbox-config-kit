import { assertValidSingBoxCoreConfig } from "./validation.js";
import type {
  CreateHysteria2InboundOptions,
  CreateSingBoxCoreConfigOptions,
  CreateSingBoxCorePayloadOptions,
  JsonValue,
  SingBoxCoreConfig,
  SingBoxCorePayload,
  SingBoxHysteria2Inbound
} from "./types.js";

export function createHysteria2InboundConfig(options: CreateHysteria2InboundOptions): SingBoxHysteria2Inbound {
  const tls: Record<string, JsonValue> = { enabled: true };
  if (options.tls.serverName) tls.server_name = options.tls.serverName;
  if (options.tls.alpn && options.tls.alpn.length > 0) tls.alpn = [...options.tls.alpn];
  if (options.tls.minVersion) tls.min_version = options.tls.minVersion;
  if (options.tls.maxVersion) tls.max_version = options.tls.maxVersion;
  if (options.tls.cipherSuites && options.tls.cipherSuites.length > 0) tls.cipher_suites = [...options.tls.cipherSuites];
  // Path-mode fields are emitted whenever present (even ""), mirroring the Xray inbound TLS
  // certificate path/content toggle, which always writes both keys once that mode is chosen.
  if (options.tls.certificatePath !== undefined) tls.certificate_path = options.tls.certificatePath;
  if (options.tls.keyPath !== undefined) tls.key_path = options.tls.keyPath;
  if (options.tls.certificate !== undefined) {
    tls.certificate = (typeof options.tls.certificate === "string" ? options.tls.certificate : [...options.tls.certificate]) as JsonValue;
  }
  if (options.tls.key !== undefined) {
    tls.key = (typeof options.tls.key === "string" ? options.tls.key : [...options.tls.key]) as JsonValue;
  }
  // ech/acme are prebuilt by the form layer and assigned verbatim; both are off by default.
  if (options.tls.ech) tls.ech = options.tls.ech;
  if (options.tls.acme) tls.acme = options.tls.acme;

  const inbound: Record<string, JsonValue> = {
    type: "hysteria2",
    tag: options.tag,
    listen: options.listen ?? "::",
    listen_port: options.listenPort,
    // The panel injects real users into the running node config at sync time; this kit
    // never represents or edits users, so it is always emitted empty here.
    users: [],
    tls: tls as JsonValue
  };

  if (options.upMbps !== undefined) inbound.up_mbps = options.upMbps;
  if (options.downMbps !== undefined) inbound.down_mbps = options.downMbps;
  if (options.ignoreClientBandwidth !== undefined) inbound.ignore_client_bandwidth = options.ignoreClientBandwidth;
  if (options.udpTimeout) inbound.udp_timeout = options.udpTimeout;
  if (options.udpFragment !== undefined) inbound.udp_fragment = options.udpFragment;
  if (options.brutalDebug !== undefined) inbound.brutal_debug = options.brutalDebug;
  if (options.obfs) {
    inbound.obfs = { type: "salamander", password: options.obfs.password } as JsonValue;
  }
  if (options.masquerade) inbound.masquerade = options.masquerade as JsonValue;
  // Panel-only metadata for subscription-link port hopping; the panel strips it before the node.
  if (options.portHoppingRange) inbound.port_hopping_range = options.portHoppingRange;

  return inbound as SingBoxHysteria2Inbound;
}

function configFromOptions(options: CreateSingBoxCoreConfigOptions): Record<string, JsonValue> {
  return {
    log: { level: options.logLevel ?? "info" },
    inbounds: options.inbounds.map(createHysteria2InboundConfig) as unknown as JsonValue,
    outbounds: [{ type: "direct" }] as JsonValue
  };
}

export function createSingBoxCoreConfig(options: CreateSingBoxCoreConfigOptions): SingBoxCoreConfig {
  return assertValidSingBoxCoreConfig(configFromOptions(options));
}

export function generateSingBoxCoreConfigJson(options: CreateSingBoxCoreConfigOptions, space = 2): string {
  return JSON.stringify(createSingBoxCoreConfig(options), null, space);
}

export function createSingBoxCorePayload(options: CreateSingBoxCorePayloadOptions): SingBoxCorePayload {
  const { name = "singbox_core", ...configOptions } = options;
  return {
    name,
    type: "singbox",
    config: createSingBoxCoreConfig(configOptions),
    exclude_inbound_tags: [],
    fallbacks_inbound_tags: []
  };
}
