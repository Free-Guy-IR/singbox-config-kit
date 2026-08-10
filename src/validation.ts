import { z } from "zod";
import type {
  JsonValue,
  SingBoxCoreConfig,
  SingBoxHysteria2Inbound,
  SingBoxValidationIssue,
  SingBoxValidationResult
} from "./types.js";

const jsonValueSchema: z.ZodType<JsonValue> = z.lazy(() =>
  z.union([
    z.string(),
    z.number().finite(),
    z.boolean(),
    z.null(),
    z.array(jsonValueSchema),
    z.record(jsonValueSchema)
  ])
);

const tlsSchema = z
  .object({
    enabled: z.boolean(),
    server_name: z.string().optional(),
    alpn: z.array(z.string()).optional(),
    min_version: z.string().optional(),
    max_version: z.string().optional(),
    cipher_suites: z.array(z.string()).optional(),
    certificate_path: z.string().optional(),
    key_path: z.string().optional(),
    certificate: z.union([z.string(), z.array(z.string())]).optional(),
    key: z.union([z.string(), z.array(z.string())]).optional(),
    // ech/acme are nested objects handled structurally by the node/core; passed through as-is.
    ech: z.record(jsonValueSchema).optional(),
    acme: z.record(jsonValueSchema).optional()
  })
  .catchall(jsonValueSchema);

const masqueradeObjectSchema = z
  .object({
    type: z.enum(["file", "proxy", "string"])
  })
  .catchall(jsonValueSchema);

const masqueradeSchema = z.union([
  z.string().refine(v => /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(v), {
    message: "masquerade must be a full URL including a scheme, e.g. https://example.com (a bare domain is rejected by sing-box itself with 'unknown masquerade URL scheme')"
  }),
  masqueradeObjectSchema
]);

const obfsSchema = z
  .object({
    type: z.literal("salamander"),
    password: z.string()
  })
  .catchall(jsonValueSchema);

// Scope (v1): only the hysteria2 inbound type is recognized, mirroring the Python-side
// SingBoxConfig docstring ("unlike XRayConfig's network_handlers registry, there is
// intentionally no generic multi-protocol resolver yet").
const hysteria2InboundSchema = z
  .object({
    type: z.literal("hysteria2"),
    tag: z.string(),
    listen: z.string().optional(),
    listen_port: z.number(),
    users: z.array(jsonValueSchema).optional(),
    up_mbps: z.number().optional(),
    down_mbps: z.number().optional(),
    ignore_client_bandwidth: z.boolean().optional(),
    udp_timeout: z.union([z.string(), z.number()]).optional(),
    udp_fragment: z.boolean().optional(),
    brutal_debug: z.boolean().optional(),
    // Panel-only metadata for subscription-link port hopping; stripped before the node.
    port_hopping_range: z.string().optional(),
    obfs: obfsSchema.optional(),
    masquerade: masqueradeSchema.optional(),
    tls: tlsSchema
  })
  .catchall(jsonValueSchema);

const outboundSchema = z
  .object({
    type: z.string()
  })
  .catchall(jsonValueSchema);

const rawSingBoxCoreConfigSchema = z
  .object({
    log: z.record(jsonValueSchema).optional(),
    inbounds: z.array(hysteria2InboundSchema),
    outbounds: z.array(outboundSchema)
  })
  .catchall(jsonValueSchema);

function issue(path: string, code: string, message: string): SingBoxValidationIssue {
  return { path, code, message };
}

function pathForZod(path: readonly (string | number)[]): string {
  if (path.length === 0) return "/";
  return `/${path.map(String).join("/")}`;
}

function validateListenPort(value: number, path: string): void {
  if (!Number.isInteger(value) || value <= 0 || value > 65535) {
    throw new Error(`${path}: listen_port must be an integer between 1 and 65535.`);
  }
}

/** Mirrors SingBoxConfig._validate_hysteria2_inbound: hysteria2 always requires tls.enabled. */
function validateHysteria2Inbound(inbound: z.infer<typeof hysteria2InboundSchema>, index: number): void {
  const path = `/inbounds/${index}`;
  const tag = inbound.tag.trim();
  if (!tag) {
    throw new Error(`${path}/tag: all inbounds must have a unique tag.`);
  }
  validateListenPort(inbound.listen_port, `${path}/listen_port`);
  if (inbound.tls.enabled !== true) {
    throw new Error(`${path}/tls/enabled: ${tag}: hysteria2 inbound requires tls to be enabled.`);
  }
  if (inbound.obfs && !inbound.obfs.password.trim()) {
    throw new Error(`${path}/obfs/password: obfs password is required when obfs is configured.`);
  }
}

/** Mirrors SingBoxConfig._validate: unique non-empty tags, >=1 inbound, >=1 outbound. */
function normalizeConfig(input: z.infer<typeof rawSingBoxCoreConfigSchema>): SingBoxCoreConfig {
  if (input.inbounds.length === 0) {
    throw new Error("/inbounds: config doesn't have inbounds.");
  }
  if (input.outbounds.length === 0) {
    throw new Error("/outbounds: config doesn't have outbounds.");
  }

  const seenTags = new Set<string>();
  input.inbounds.forEach((inbound, index) => {
    validateHysteria2Inbound(inbound, index);
    const tag = inbound.tag.trim();
    if (seenTags.has(tag)) {
      throw new Error(`/inbounds/${index}/tag: duplicate inbound tag: ${tag}.`);
    }
    seenTags.add(tag);
  });

  return input as SingBoxCoreConfig;
}

export function validateSingBoxCoreConfig(input: unknown): SingBoxValidationResult {
  const parsed = rawSingBoxCoreConfigSchema.safeParse(input);
  if (!parsed.success) {
    return {
      ok: false,
      issues: parsed.error.issues.map(zodIssue =>
        issue(
          pathForZod(zodIssue.path.filter((part): part is string | number => typeof part === "string" || typeof part === "number")),
          "SB_SCHEMA_INVALID_CORE_CONFIG",
          zodIssue.message
        )
      )
    };
  }

  const issues: SingBoxValidationIssue[] = [];
  let config: SingBoxCoreConfig | undefined;

  try {
    config = normalizeConfig(parsed.data);
  } catch (error) {
    const rawMessage = error instanceof Error ? error.message : "Invalid sing-box core config.";
    const match = rawMessage.match(/^(\/[^:]*):\s*(.+)$/);
    issues.push(issue(match?.[1] ?? "/", "SB_SEMANTIC_INVALID_CORE_CONFIG", match?.[2] ?? rawMessage));
  }

  if (!config) return { ok: false, issues };
  return { ok: true, config, issues: [] };
}

export function assertValidSingBoxCoreConfig(input: unknown): SingBoxCoreConfig {
  const result = validateSingBoxCoreConfig(input);
  if (!result.ok) {
    const firstIssue = result.issues[0];
    throw new Error(firstIssue ? `${firstIssue.path}: ${firstIssue.message}` : "Invalid sing-box core config.");
  }
  return result.config;
}

export function isHysteria2Inbound(value: unknown): value is SingBoxHysteria2Inbound {
  return !!value && typeof value === "object" && (value as Record<string, unknown>).type === "hysteria2";
}
