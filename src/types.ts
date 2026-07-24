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
  /** Filesystem paths on the node. Mutually exclusive with certificate/key (inline content). */
  readonly certificate_path?: string;
  readonly key_path?: string;
  /** Inline PEM content, as a single string or an array of lines. Mutually exclusive with the *_path fields. */
  readonly certificate?: string | readonly string[];
  readonly key?: string | readonly string[];
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
  readonly obfs?: SingBoxHysteria2Obfs;
  readonly masquerade?: string;
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
  readonly obfs?: { readonly password: string };
  readonly masquerade?: string;
  readonly tls: {
    readonly serverName?: string;
    readonly alpn?: readonly string[];
    readonly certificatePath?: string;
    readonly keyPath?: string;
    readonly certificate?: string | readonly string[];
    readonly key?: string | readonly string[];
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
