import { assertValidSingBoxCoreConfig } from "./validation.js";
import type {
  CreateInboundOptions,
  CreateShadowsocksInboundOptions,
  CreateSingBoxCoreConfigOptions,
  CreateSingBoxCorePayloadOptions,
  CreateTlsOptions,
  CreateTransportOptions,
  CreateTuicInboundOptions,
  CreateHysteria2InboundOptions,
  CreateVlessInboundOptions,
  CreateVmessInboundOptions,
  CreateTrojanInboundOptions,
  JsonValue,
  SingBoxCoreConfig,
  SingBoxCorePayload,
  SingBoxHysteria2Inbound,
  SingBoxInbound
} from "./types.js";

/** Builds the shared `tls` wire object from camelCase options. Returns undefined when TLS is off. */
function buildTls(options: CreateTlsOptions | undefined, forceEnabled = false): JsonValue | undefined {
  if (!options) return forceEnabled ? { enabled: true } : undefined;
  if (options.enabled === false && !forceEnabled) return undefined;

  const tls: Record<string, JsonValue> = { enabled: true };
  if (options.serverName) tls.server_name = options.serverName;
  if (options.alpn && options.alpn.length > 0) tls.alpn = [...options.alpn];
  if (options.minVersion) tls.min_version = options.minVersion;
  if (options.maxVersion) tls.max_version = options.maxVersion;
  if (options.cipherSuites && options.cipherSuites.length > 0) tls.cipher_suites = [...options.cipherSuites];
  // Path-mode fields are emitted whenever present (even ""), mirroring the Xray inbound TLS
  // certificate path/content toggle, which always writes both keys once that mode is chosen.
  if (options.certificatePath !== undefined) tls.certificate_path = options.certificatePath;
  if (options.keyPath !== undefined) tls.key_path = options.keyPath;
  if (options.certificate !== undefined) {
    tls.certificate = (typeof options.certificate === "string" ? options.certificate : [...options.certificate]) as JsonValue;
  }
  if (options.key !== undefined) {
    tls.key = (typeof options.key === "string" ? options.key : [...options.key]) as JsonValue;
  }
  // ech/acme/utls/reality are prebuilt by the form layer and assigned verbatim; all off by default.
  if (options.ech) tls.ech = options.ech;
  if (options.acme) tls.acme = options.acme;
  if (options.utls) tls.utls = options.utls;
  if (options.reality) tls.reality = options.reality;
  return tls;
}

/** Builds the shared V2Ray `transport` wire object. Returns undefined for tcp (no transport). */
function buildTransport(options: CreateTransportOptions | undefined): JsonValue | undefined {
  if (!options || !options.type) return undefined;
  const transport: Record<string, JsonValue> = { type: options.type };
  switch (options.type) {
    case "ws":
      if (options.path) transport.path = options.path;
      if (options.host) transport.headers = { Host: options.host };
      break;
    case "httpupgrade":
      if (options.path) transport.path = options.path;
      if (options.host) transport.host = options.host;
      break;
    case "grpc":
      if (options.serviceName) transport.service_name = options.serviceName;
      break;
    case "http":
      if (options.path) transport.path = options.path;
      if (options.host) transport.host = [options.host];
      if (options.method) transport.method = options.method;
      break;
  }
  return transport;
}

/** Common head shared by every inbound: type/tag/listen/listen_port and the always-empty users. */
function inboundHead(type: string, options: { tag: string; listen?: string; listenPort: number }): Record<string, JsonValue> {
  return {
    type,
    tag: options.tag,
    listen: options.listen ?? "::",
    listen_port: options.listenPort,
    // The panel injects real users into the running node config at sync time; this kit
    // never represents or edits users, so it is always emitted empty here.
    users: []
  };
}

export function createVlessInboundConfig(options: CreateVlessInboundOptions): SingBoxInbound {
  const inbound = inboundHead("vless", options);
  const tls = buildTls(options.tls);
  if (tls) inbound.tls = tls;
  const transport = buildTransport(options.transport);
  if (transport) inbound.transport = transport;
  return inbound as unknown as SingBoxInbound;
}

export function createVmessInboundConfig(options: CreateVmessInboundOptions): SingBoxInbound {
  const inbound = inboundHead("vmess", options);
  const tls = buildTls(options.tls);
  if (tls) inbound.tls = tls;
  const transport = buildTransport(options.transport);
  if (transport) inbound.transport = transport;
  return inbound as unknown as SingBoxInbound;
}

export function createTrojanInboundConfig(options: CreateTrojanInboundOptions): SingBoxInbound {
  const inbound = inboundHead("trojan", options);
  const tls = buildTls(options.tls);
  if (tls) inbound.tls = tls;
  const transport = buildTransport(options.transport);
  if (transport) inbound.transport = transport;
  return inbound as unknown as SingBoxInbound;
}

export function createShadowsocksInboundConfig(options: CreateShadowsocksInboundOptions): SingBoxInbound {
  const inbound = inboundHead("shadowsocks", options);
  inbound.method = options.method;
  inbound.password = options.password ?? "";
  return inbound as unknown as SingBoxInbound;
}

export function createTuicInboundConfig(options: CreateTuicInboundOptions): SingBoxInbound {
  const inbound = inboundHead("tuic", options);
  if (options.congestionControl) inbound.congestion_control = options.congestionControl;
  inbound.tls = buildTls(options.tls, true) ?? { enabled: true };
  return inbound as unknown as SingBoxInbound;
}

export function createHysteria2InboundConfig(options: CreateHysteria2InboundOptions): SingBoxHysteria2Inbound {
  const inbound = inboundHead("hysteria2", options);
  inbound.tls = buildTls(options.tls, true) ?? { enabled: true };

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

  return inbound as unknown as SingBoxHysteria2Inbound;
}

/** Dispatches to the per-protocol inbound builder based on the options' discriminant. */
export function createInboundConfig(options: CreateInboundOptions): SingBoxInbound {
  switch (options.protocol) {
    case "vless":
      return createVlessInboundConfig(options);
    case "vmess":
      return createVmessInboundConfig(options);
    case "trojan":
      return createTrojanInboundConfig(options);
    case "shadowsocks":
      return createShadowsocksInboundConfig(options);
    case "tuic":
      return createTuicInboundConfig(options);
    case "hysteria2":
    case undefined:
      return createHysteria2InboundConfig(options as CreateHysteria2InboundOptions);
    default: {
      const exhaustive: never = options;
      throw new Error(`unknown sing-box inbound protocol: ${JSON.stringify(exhaustive)}`);
    }
  }
}

function configFromOptions(options: CreateSingBoxCoreConfigOptions): Record<string, JsonValue> {
  return {
    log: { level: options.logLevel ?? "info" },
    inbounds: options.inbounds.map(createInboundConfig) as unknown as JsonValue,
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
