import { describe, expect, it } from "bun:test";
import {
  createDefaultHysteria2InboundDraft,
  createDefaultSingBoxCoreDraft,
  createHysteria2InboundConfig,
  createSingBoxCoreConfig,
  createSingBoxCoreConfigFromDraft,
  createSingBoxCorePayload,
  generateSingBoxCoreConfigJson,
  generateSingBoxCoreConfigJsonFromDraft,
  validateSingBoxCoreConfig,
  validateSingBoxCoreDraft
} from "../src/index.js";

describe("singbox-config-kit", () => {
  it("creates a minimal default hysteria2 core config", () => {
    const config = createSingBoxCoreConfig({
      inbounds: [
        {
          tag: "Hysteria2",
          listenPort: 8443,
          tls: { serverName: "example.com", certificatePath: "/etc/x/fullchain.pem", keyPath: "/etc/x/key.pem" }
        }
      ]
    });

    expect(config).toEqual({
      log: { level: "info" },
      inbounds: [
        {
          type: "hysteria2",
          tag: "Hysteria2",
          listen: "::",
          listen_port: 8443,
          users: [],
          tls: {
            enabled: true,
            server_name: "example.com",
            certificate_path: "/etc/x/fullchain.pem",
            key_path: "/etc/x/key.pem"
          }
        }
      ],
      outbounds: [{ type: "direct" }]
    });

    const json = generateSingBoxCoreConfigJson({ inbounds: [{ tag: "Hysteria2", listenPort: 8443, tls: {} }] });
    expect(JSON.parse(json)).toMatchObject({ inbounds: [{ type: "hysteria2", tag: "Hysteria2" }] });
  });

  it("supports obfs, masquerade, alpn, and inline TLS content", () => {
    const inbound = createHysteria2InboundConfig({
      tag: "Hysteria2",
      listenPort: 8443,
      upMbps: 100,
      downMbps: 100,
      ignoreClientBandwidth: true,
      obfs: { password: "s3cr3t" },
      masquerade: "https://example.com",
      tls: { alpn: ["h3"], certificate: ["-----BEGIN CERTIFICATE-----", "abc", "-----END CERTIFICATE-----"], key: "single-line-key" }
    });

    expect(inbound).toMatchObject({
      up_mbps: 100,
      down_mbps: 100,
      ignore_client_bandwidth: true,
      obfs: { type: "salamander", password: "s3cr3t" },
      masquerade: "https://example.com",
      tls: { enabled: true, alpn: ["h3"], key: "single-line-key" }
    });
  });

  it("rejects hysteria2 inbounds without tls.enabled, duplicate tags, missing inbounds/outbounds, and bad ports", () => {
    expect(validateSingBoxCoreConfig({ inbounds: [], outbounds: [{ type: "direct" }] }).ok).toBe(false);
    expect(validateSingBoxCoreConfig({ inbounds: [{ type: "hysteria2", tag: "a", listen_port: 1, tls: { enabled: true } }], outbounds: [] }).ok).toBe(false);

    const disabledTls = validateSingBoxCoreConfig({
      inbounds: [{ type: "hysteria2", tag: "a", listen_port: 8443, tls: { enabled: false } }],
      outbounds: [{ type: "direct" }]
    });
    expect(disabledTls.ok).toBe(false);

    const dup = validateSingBoxCoreConfig({
      inbounds: [
        { type: "hysteria2", tag: "a", listen_port: 8443, tls: { enabled: true } },
        { type: "hysteria2", tag: "a", listen_port: 8444, tls: { enabled: true } }
      ],
      outbounds: [{ type: "direct" }]
    });
    expect(dup.ok).toBe(false);

    const badPort = validateSingBoxCoreConfig({
      inbounds: [{ type: "hysteria2", tag: "a", listen_port: 70000, tls: { enabled: true } }],
      outbounds: [{ type: "direct" }]
    });
    expect(badPort.ok).toBe(false);

    const ok = validateSingBoxCoreConfig({
      inbounds: [{ type: "hysteria2", tag: "a", listen_port: 8443, tls: { enabled: true } }],
      outbounds: [{ type: "direct" }]
    });
    expect(ok.ok).toBe(true);
  });

  it("builds a create payload shaped for the panel API", () => {
    const payload = createSingBoxCorePayload({ name: "my-singbox", inbounds: [{ tag: "Hysteria2", listenPort: 8443, tls: {} }] });
    expect(payload).toMatchObject({
      name: "my-singbox",
      type: "singbox",
      exclude_inbound_tags: [],
      fallbacks_inbound_tags: []
    });
    expect(payload.config.inbounds).toHaveLength(1);
  });

  it("creates unique default inbound drafts and round-trips through draft -> config", () => {
    const draft = createDefaultSingBoxCoreDraft();
    expect(draft.inbounds).toHaveLength(1);
    expect(draft.inbounds[0]!.tag).toBe("Hysteria2");

    const second = createDefaultHysteria2InboundDraft(draft.inbounds.map(i => i.tag));
    expect(second.tag).toBe("Hysteria2_2");

    const draftWithTwo = { ...draft, inbounds: [...draft.inbounds, second] };
    expect(validateSingBoxCoreDraft(draftWithTwo)).toEqual([]);

    const config = createSingBoxCoreConfigFromDraft(draftWithTwo);
    expect(config.inbounds).toHaveLength(2);
    expect(config.inbounds.every(i => Array.isArray(i.users) && i.users.length === 0)).toBe(true);

    const json = generateSingBoxCoreConfigJsonFromDraft(draftWithTwo);
    expect(JSON.parse(json)).toEqual(config);
  });

  it("flags duplicate tags and missing obfs password at the draft level", () => {
    const draft = createDefaultSingBoxCoreDraft();
    const dupTagDraft = { ...draft, inbounds: [draft.inbounds[0]!, { ...draft.inbounds[0]! }] };
    const dupIssues = validateSingBoxCoreDraft(dupTagDraft);
    expect(dupIssues.some(i => i.code === "SB_FORM_TAG_DUPLICATE")).toBe(true);

    const obfsDraft = { ...draft, inbounds: [{ ...draft.inbounds[0]!, obfsEnabled: true, obfsPassword: "" }] };
    const obfsIssues = validateSingBoxCoreDraft(obfsDraft);
    expect(obfsIssues.some(i => i.code === "SB_FORM_OBFS_PASSWORD_REQUIRED")).toBe(true);
  });

  it("maps certMode 'path' vs 'content' to certificate_path/key_path vs certificate/key", () => {
    const draft = createDefaultSingBoxCoreDraft();
    const pathDraft = {
      ...draft,
      inbounds: [{ ...draft.inbounds[0]!, certMode: "path" as const, certificateFile: "/a/fullchain.pem", keyFile: "/a/key.pem" }]
    };
    const pathConfig = createSingBoxCoreConfigFromDraft(pathDraft);
    expect(pathConfig.inbounds[0]!.tls).toMatchObject({ certificate_path: "/a/fullchain.pem", key_path: "/a/key.pem" });
    expect(pathConfig.inbounds[0]!.tls.certificate).toBeUndefined();

    const contentDraft = {
      ...draft,
      inbounds: [{ ...draft.inbounds[0]!, certMode: "content" as const, certificate: "line1\nline2", key: "keyline" }]
    };
    const contentConfig = createSingBoxCoreConfigFromDraft(contentDraft);
    expect(contentConfig.inbounds[0]!.tls).toMatchObject({ certificate: ["line1", "line2"], key: ["keyline"] });
    expect(contentConfig.inbounds[0]!.tls.certificate_path).toBeUndefined();
  });
});
