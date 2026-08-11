import { z } from "zod";
import type {
  JsonValue,
  SingBoxCoreConfig,
  SingBoxHysteria2Inbound,
  SingBoxInboundType,
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

/** The inbound `type` values this kit recognizes. */
const SUPPORTED_INBOUND_TYPES: readonly SingBoxInboundType[] = [
  "vless",
  "vmess",
  "trojan",
  "shadowsocks",
  "tuic",
  "hysteria2"
];

/**
 * Generic inbound schema: strict about the fields the rest of the panel keys on
 * (type/tag/listen_port), permissive (`.catchall`) about everything else, since the
 * per-protocol wire shape is large and validated structurally at build time. Per-type
 * semantic rules (tls required, shadowsocks method required, ...) run in normalizeConfig.
 */
const inboundSchema = z
  .object({
    type: z.enum(SUPPORTED_INBOUND_TYPES as unknown as [string, ...string[]]),
    tag: z.string(),
    listen: z.string().optional(),
    listen_port: z.number(),
    users: z.array(jsonValueSchema).optional()
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
    inbounds: z.array(inboundSchema),
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

function asObject(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
}

/** Per-type semantic validation, mirroring the panel-side SingBoxConfig validators. */
function validateInbound(inbound: z.infer<typeof inboundSchema>, index: number): void {
  const path = `/inbounds/${index}`;
  const tag = inbound.tag.trim();
  if (!tag) {
    throw new Error(`${path}/tag: all inbounds must have a unique tag.`);
  }
  validateListenPort(inbound.listen_port, `${path}/listen_port`);

  // tls/obfs/method arrive through the schema's permissive `.catchall`, so they are not
  // on the statically-inferred shape; read them off the raw record.
  const rec = inbound as Record<string, unknown>;
  const tls = asObject(rec.tls);
  switch (inbound.type) {
    case "hysteria2": {
      if (!tls || tls.enabled !== true) {
        throw new Error(`${path}/tls/enabled: ${tag}: hysteria2 inbound requires tls to be enabled.`);
      }
      const obfs = asObject(rec.obfs);
      if (obfs && (typeof obfs.password !== "string" || !obfs.password.trim())) {
        throw new Error(`${path}/obfs/password: obfs password is required when obfs is configured.`);
      }
      break;
    }
    case "tuic": {
      if (!tls || tls.enabled !== true) {
        throw new Error(`${path}/tls/enabled: ${tag}: tuic inbound requires tls to be enabled.`);
      }
      break;
    }
    case "shadowsocks": {
      if (typeof rec.method !== "string" || !rec.method.trim()) {
        throw new Error(`${path}/method: ${tag}: shadowsocks inbound requires a method.`);
      }
      break;
    }
    // vless/vmess/trojan: tls is optional; nothing extra required at this layer.
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
    validateInbound(inbound, index);
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
