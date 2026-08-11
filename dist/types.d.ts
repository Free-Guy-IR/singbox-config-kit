export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];
export type JsonObject = {
    readonly [key: string]: JsonValue;
};
/** REALITY server settings, shared by the stream-security protocols (vless/vmess/trojan/tuic). */
export type SingBoxReality = JsonObject & {
    readonly enabled: true;
    readonly handshake: JsonObject & {
        readonly server: string;
        readonly server_port: number;
    };
    readonly private_key: string;
    readonly short_id?: readonly string[];
    readonly max_time_difference?: string;
};
/** uTLS client-fingerprint spoofing, shared by the stream-security protocols. */
export type SingBoxUtls = JsonObject & {
    readonly enabled: boolean;
    readonly fingerprint?: string;
};
/**
 * TLS block shared by every TLS-bearing sing-box inbound (hysteria2 has used this
 * shape already; vless/vmess/trojan/tuic reuse it and additionally may carry
 * `reality`/`utls`).
 */
export type SingBoxTls = JsonObject & {
    readonly enabled: boolean;
    readonly server_name?: string;
    readonly alpn?: readonly string[];
    readonly min_version?: string;
    readonly max_version?: string;
    readonly cipher_suites?: readonly string[];
    /** Filesystem paths on the node. Mutually exclusive with certificate/key (inline content). */
    readonly certificate_path?: string;
    readonly key_path?: string;
    /** Inline PEM content, as a single string or an array of lines. Mutually exclusive with *_path. */
    readonly certificate?: string | readonly string[];
    readonly key?: string | readonly string[];
    /** Encrypted Client Hello. */
    readonly ech?: JsonObject;
    /** ACME auto-certificate. Mutually exclusive with certificate/key. */
    readonly acme?: JsonObject;
    /** uTLS client fingerprint. */
    readonly utls?: SingBoxUtls;
    /** REALITY. Mutually exclusive with certificate/key/acme. */
    readonly reality?: SingBoxReality;
};
/** V2Ray transport, shared by vless/vmess/trojan. tcp is represented by the absence of `transport`. */
export type SingBoxTransport = JsonObject & {
    readonly type: "ws" | "grpc" | "http" | "httpupgrade";
    readonly path?: string;
    readonly headers?: JsonObject;
    readonly host?: string | readonly string[];
    readonly service_name?: string;
    readonly method?: string;
};
export type SingBoxHysteria2Obfs = JsonObject & {
    readonly type: "salamander";
    readonly password: string;
};
/**
 * Masquerade as an object (the long form). sing-box also accepts a bare URL string as a
 * shorthand for `{ type: "proxy", url }`; both forms are represented on the inbound below.
 */
export type SingBoxHysteria2Masquerade = JsonObject & {
    readonly type: "file" | "proxy" | "string";
    readonly directory?: string;
    readonly url?: string;
    readonly rewrite_host?: boolean;
    readonly status_code?: number;
    readonly headers?: JsonObject;
    readonly content?: string;
};
/** Fields every user-facing sing-box inbound carries. `users` is always emitted empty here. */
type SingBoxInboundCommon = JsonObject & {
    readonly tag: string;
    readonly listen: string;
    readonly listen_port: number;
    /** Always emitted as []. The panel injects real users at node-sync time; never edited here. */
    readonly users: readonly JsonValue[];
};
export type SingBoxVlessInbound = SingBoxInboundCommon & {
    readonly type: "vless";
    readonly tls?: SingBoxTls;
    readonly transport?: SingBoxTransport;
};
export type SingBoxVmessInbound = SingBoxInboundCommon & {
    readonly type: "vmess";
    readonly tls?: SingBoxTls;
    readonly transport?: SingBoxTransport;
};
export type SingBoxTrojanInbound = SingBoxInboundCommon & {
    readonly type: "trojan";
    readonly tls?: SingBoxTls;
    readonly transport?: SingBoxTransport;
};
export type SingBoxShadowsocksInbound = SingBoxInboundCommon & {
    readonly type: "shadowsocks";
    /** Inbound-level cipher; required. Per-user password is injected at node-sync time. */
    readonly method: string;
    /** Server key (base64) for the 2022 methods; empty for the legacy ciphers. */
    readonly password: string;
};
export type SingBoxTuicInbound = SingBoxInboundCommon & {
    readonly type: "tuic";
    readonly congestion_control?: string;
    readonly tls: SingBoxTls;
};
export type SingBoxHysteria2Inbound = SingBoxInboundCommon & {
    readonly type: "hysteria2";
    readonly up_mbps?: number;
    readonly down_mbps?: number;
    readonly ignore_client_bandwidth?: boolean;
    readonly udp_timeout?: string;
    readonly udp_fragment?: boolean;
    readonly brutal_debug?: boolean;
    readonly obfs?: SingBoxHysteria2Obfs;
    readonly masquerade?: string | SingBoxHysteria2Masquerade;
    /**
     * Panel-only metadata: the port range advertised in subscription links for QUIC port
     * hopping. Stripped from the config before it reaches the node (see the panel's
     * _PANEL_ONLY_INBOUND_KEYS); never a real sing-box wire key.
     */
    readonly port_hopping_range?: string;
    readonly tls: SingBoxTls;
};
/** Discriminated union of every sing-box inbound type this kit understands. */
export type SingBoxInbound = SingBoxVlessInbound | SingBoxVmessInbound | SingBoxTrojanInbound | SingBoxShadowsocksInbound | SingBoxTuicInbound | SingBoxHysteria2Inbound;
export type SingBoxInboundType = SingBoxInbound["type"];
/** sing-box release the config targets. Drives the 1.11/1.12 DNS-server + route-action shape. */
export type SingBoxVersion = "1.11" | "1.12";
/**
 * Outbound wire object. Modelled loosely (JsonObject + a known `type`/`tag`) so the editor can
 * carry every outbound kind — direct/block/socks/http/shadowsocks/vmess/vless/trojan/hysteria2/
 * tuic/anytls/ssh/dns/selector/urltest — and round-trip unknown fields untouched. The node
 * validates the exact schema; the kit only guarantees `type` (+ `tag` for the referenceable ones).
 */
export type SingBoxOutbound = JsonObject & {
    readonly type: string;
    readonly tag?: string;
};
/** A single route rule (matchers + action). Kept as a permissive JsonObject — see SingBoxRoute. */
export type SingBoxRouteRule = JsonObject;
/** A route rule-set (inline | local | remote). */
export type SingBoxRuleSet = JsonObject & {
    readonly type: string;
    readonly tag: string;
};
/** `route` section. Rules + rule-sets + defaults; permissive so unmodelled keys pass through. */
export type SingBoxRoute = JsonObject & {
    readonly rules?: readonly SingBoxRouteRule[];
    readonly rule_set?: readonly SingBoxRuleSet[];
    readonly final?: string;
    readonly auto_detect_interface?: boolean;
    readonly default_mark?: number;
};
/** A DNS server entry. 1.11 uses `{address}`, 1.12 uses `{type,server}`; both allowed here. */
export type SingBoxDnsServer = JsonObject;
/** A DNS rule (matchers + target server). */
export type SingBoxDnsRule = JsonObject;
/** `dns` section. */
export type SingBoxDns = JsonObject & {
    readonly servers?: readonly SingBoxDnsServer[];
    readonly rules?: readonly SingBoxDnsRule[];
    readonly final?: string;
    readonly strategy?: string;
    readonly disable_cache?: boolean;
    readonly disable_expire?: boolean;
    readonly fakeip?: JsonObject;
};
/** `experimental` section (clash_api + cache_file). Permissive JsonObject. */
export type SingBoxExperimental = JsonObject;
export type SingBoxCoreConfig = JsonObject & {
    readonly log?: JsonObject;
    readonly inbounds: readonly SingBoxInbound[];
    readonly outbounds: readonly SingBoxOutbound[];
    readonly route?: SingBoxRoute;
    readonly dns?: SingBoxDns;
    readonly experimental?: SingBoxExperimental;
};
export type SingBoxCorePayload = {
    readonly name: string;
    readonly type: "singbox";
    readonly config: SingBoxCoreConfig;
    readonly exclude_inbound_tags: readonly string[];
    /** sing-box cores reject a non-empty fallbacks_inbound_tags server-side; always []. */
    readonly fallbacks_inbound_tags: readonly string[];
};
/** Options for the shared TLS builder (camelCase surface; builders emit the snake_case wire keys). */
export type CreateTlsOptions = {
    readonly enabled?: boolean;
    readonly serverName?: string;
    readonly alpn?: readonly string[];
    readonly minVersion?: string;
    readonly maxVersion?: string;
    readonly cipherSuites?: readonly string[];
    readonly certificatePath?: string;
    readonly keyPath?: string;
    readonly certificate?: string | readonly string[];
    readonly key?: string | readonly string[];
    /** Prebuilt nested wire objects (built by the form layer); assigned verbatim when present. */
    readonly ech?: JsonObject;
    readonly acme?: JsonObject;
    readonly utls?: JsonObject;
    readonly reality?: JsonObject;
};
/** Options for the shared V2Ray transport builder. `type: ""` (or undefined) means tcp -> no transport. */
export type CreateTransportOptions = {
    readonly type?: "" | "ws" | "grpc" | "http" | "httpupgrade";
    readonly path?: string;
    readonly host?: string;
    readonly serviceName?: string;
    readonly method?: string;
};
type CreateInboundCommonOptions = {
    readonly tag: string;
    readonly listen?: string;
    readonly listenPort: number;
};
export type CreateVlessInboundOptions = CreateInboundCommonOptions & {
    readonly protocol: "vless";
    readonly tls?: CreateTlsOptions;
    readonly transport?: CreateTransportOptions;
};
export type CreateVmessInboundOptions = CreateInboundCommonOptions & {
    readonly protocol: "vmess";
    readonly tls?: CreateTlsOptions;
    readonly transport?: CreateTransportOptions;
};
export type CreateTrojanInboundOptions = CreateInboundCommonOptions & {
    readonly protocol: "trojan";
    readonly tls?: CreateTlsOptions;
    readonly transport?: CreateTransportOptions;
};
export type CreateShadowsocksInboundOptions = CreateInboundCommonOptions & {
    readonly protocol: "shadowsocks";
    readonly method: string;
    readonly password?: string;
};
export type CreateTuicInboundOptions = CreateInboundCommonOptions & {
    readonly protocol: "tuic";
    readonly congestionControl?: string;
    readonly tls: CreateTlsOptions;
};
export type CreateHysteria2InboundOptions = CreateInboundCommonOptions & {
    readonly protocol?: "hysteria2";
    readonly upMbps?: number;
    readonly downMbps?: number;
    readonly ignoreClientBandwidth?: boolean;
    readonly udpTimeout?: string;
    readonly udpFragment?: boolean;
    readonly brutalDebug?: boolean;
    readonly portHoppingRange?: string;
    readonly obfs?: {
        readonly password: string;
    };
    /** Bare-URL shorthand, or the fully-shaped masquerade object; passed through as-is. */
    readonly masquerade?: string | JsonObject;
    readonly tls: CreateTlsOptions;
};
export type CreateInboundOptions = CreateVlessInboundOptions | CreateVmessInboundOptions | CreateTrojanInboundOptions | CreateShadowsocksInboundOptions | CreateTuicInboundOptions | CreateHysteria2InboundOptions;
export type CreateSingBoxCoreConfigOptions = {
    readonly logLevel?: string;
    readonly singboxVersion?: SingBoxVersion;
    readonly inbounds: readonly CreateInboundOptions[];
    /** Wire-shaped outbounds. When empty/omitted the builder emits a single `{type:"direct"}`. */
    readonly outbounds?: readonly SingBoxOutbound[];
    readonly route?: SingBoxRoute;
    readonly dns?: SingBoxDns;
    readonly experimental?: SingBoxExperimental;
};
export type CreateSingBoxCorePayloadOptions = CreateSingBoxCoreConfigOptions & {
    readonly name?: string;
};
export type SingBoxValidationIssue = {
    readonly code: string;
    readonly path: string;
    readonly message: string;
};
export type SingBoxValidationResult = {
    readonly ok: true;
    readonly config: SingBoxCoreConfig;
    readonly issues: readonly [];
} | {
    readonly ok: false;
    readonly issues: readonly SingBoxValidationIssue[];
};
export {};
//# sourceMappingURL=types.d.ts.map