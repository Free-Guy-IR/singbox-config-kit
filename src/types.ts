export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];
export type JsonObject = { readonly [key: string]: JsonValue };

export type SingBoxHysteria2Obfs = JsonObject & {
  readonly type: "salamander";
  readonly password: string;
};

export type SingBoxHysteria2Tls = JsonObject & {
  readonly enabled: boolean;
  readonly server_name?: string;
  readonly alpn?: readonly string[];
  readonly min_version?: string;
  readonly max_version?: string;
  readonly cipher_suites?: readonly string[];
  /** Filesystem paths on the node. Mutually exclusive with certificate/key (inline content). */
  readonly certificate_path?: string;
  readonly key_path?: string;
  /** Inline PEM content, as a single string or an array of lines. Mutually exclusive with the *_path fields. */
  readonly certificate?: string | readonly string[];
  readonly key?: string | readonly string[];
  /** Encrypted Client Hello. Modeled for parity with the Xray inbound TLS editor; off by default. */
  readonly ech?: JsonObject;
  /** ACME auto-certificate. Mutually exclusive with certificate/key (inline or path); off by default. */
  readonly acme?: JsonObject;
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

export type SingBoxHysteria2Inbound = JsonObject & {
  readonly type: "hysteria2";
  readonly tag: string;
  readonly listen: string;
  readonly listen_port: number;
  /** Always emitted as []. The panel injects real users at node-sync time; never edited here. */
  readonly users: readonly JsonValue[];
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
  readonly tls: SingBoxHysteria2Tls;
};

export type SingBoxOutbound = JsonObject & {
  readonly type: string;
};

export type SingBoxCoreConfig = JsonObject & {
  readonly log?: JsonObject;
  readonly inbounds: readonly SingBoxHysteria2Inbound[];
  readonly outbounds: readonly SingBoxOutbound[];
};

export type SingBoxCorePayload = {
  readonly name: string;
  readonly type: "singbox";
  readonly config: SingBoxCoreConfig;
  readonly exclude_inbound_tags: readonly string[];
  /** sing-box cores reject a non-empty fallbacks_inbound_tags server-side; always []. */
  readonly fallbacks_inbound_tags: readonly string[];
};

export type CreateHysteria2InboundOptions = {
  readonly tag: string;
  readonly listen?: string;
  readonly listenPort: number;
  readonly upMbps?: number;
  readonly downMbps?: number;
  readonly ignoreClientBandwidth?: boolean;
  readonly udpTimeout?: string;
  readonly udpFragment?: boolean;
  readonly brutalDebug?: boolean;
  readonly portHoppingRange?: string;
  readonly obfs?: { readonly password: string };
  /** Bare-URL shorthand, or the fully-shaped masquerade object; passed through as-is. */
  readonly masquerade?: string | JsonObject;
  readonly tls: {
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
  };
};

export type CreateSingBoxCoreConfigOptions = {
  readonly logLevel?: string;
  readonly inbounds: readonly CreateHysteria2InboundOptions[];
};

export type CreateSingBoxCorePayloadOptions = CreateSingBoxCoreConfigOptions & {
  readonly name?: string;
};

export type SingBoxValidationIssue = {
  readonly code: string;
  readonly path: string;
  readonly message: string;
};

export type SingBoxValidationResult =
  | {
      readonly ok: true;
      readonly config: SingBoxCoreConfig;
      readonly issues: readonly [];
    }
  | {
      readonly ok: false;
      readonly issues: readonly SingBoxValidationIssue[];
    };
