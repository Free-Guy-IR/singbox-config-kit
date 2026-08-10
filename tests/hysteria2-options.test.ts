import { describe, expect, it } from "bun:test";
import {
  createDefaultHysteria2InboundDraft,
  createHysteria2InboundConfigFromDraft,
  validateHysteria2InboundDraft,
  validateSingBoxCoreConfig
} from "../src/index.js";
import type { HysteriaInboundDraft } from "../src/index.js";

function draft(over: Partial<HysteriaInboundDraft>): HysteriaInboundDraft {
  return { ...createDefaultHysteria2InboundDraft([]), tag: "Hy2", listenPort: 8443, ...over };
}

describe("hysteria2 extended options", () => {
  it("emits a proxy masquerade object with rewrite_host", () => {
    const cfg = createHysteria2InboundConfigFromDraft(
      draft({ masqueradeType: "proxy", masquerade: "https://cf.example.com", masqueradeRewriteHost: true })
    );
    expect(cfg.masquerade).toEqual({ type: "proxy", url: "https://cf.example.com", rewrite_host: true });
  });

  it("emits a string masquerade object with status/headers/content", () => {
    const cfg = createHysteria2InboundConfigFromDraft(
      draft({ masqueradeType: "string", masqueradeStatusCode: "404", masqueradeHeaders: '{"X-A":"b"}', masqueradeContent: "nope" })
    );
    expect(cfg.masquerade).toEqual({ type: "string", status_code: 404, headers: { "X-A": "b" }, content: "nope" });
  });

  it("emits a file masquerade object", () => {
    const cfg = createHysteria2InboundConfigFromDraft(draft({ masqueradeType: "file", masqueradeDirectory: "/var/www" }));
    expect(cfg.masquerade).toEqual({ type: "file", directory: "/var/www" });
  });

  it("keeps the bare-URL string shorthand for the simple type", () => {
    const cfg = createHysteria2InboundConfigFromDraft(draft({ masqueradeType: "", masquerade: "example.com" }));
    expect(cfg.masquerade).toBe("https://example.com");
  });

  it("emits listen/advanced scalar fields", () => {
    const cfg = createHysteria2InboundConfigFromDraft(
      draft({ udpTimeout: "30s", udpFragment: true, brutalDebug: true, portHoppingRange: "20000-50000" })
    ) as Record<string, unknown>;
    expect(cfg.udp_timeout).toBe("30s");
    expect(cfg.udp_fragment).toBe(true);
    expect(cfg.brutal_debug).toBe(true);
    expect(cfg.port_hopping_range).toBe("20000-50000");
  });

  it("emits advanced TLS knobs", () => {
    const cfg = createHysteria2InboundConfigFromDraft(
      draft({ tlsMinVersion: "1.3", tlsMaxVersion: "1.3", tlsCipherSuites: ["TLS_AES_128_GCM_SHA256"] })
    );
    expect(cfg.tls.min_version).toBe("1.3");
    expect(cfg.tls.max_version).toBe("1.3");
    expect(cfg.tls.cipher_suites).toEqual(["TLS_AES_128_GCM_SHA256"]);
  });

  it("emits ech when enabled", () => {
    const cfg = createHysteria2InboundConfigFromDraft(
      draft({ echEnabled: true, echKey: "-----BEGIN ECH KEYS-----\nAAAA\n-----END ECH KEYS-----", echPqSignatureSchemesEnabled: true })
    );
    expect(cfg.tls.ech).toEqual({
      enabled: true,
      key: ["-----BEGIN ECH KEYS-----", "AAAA", "-----END ECH KEYS-----"],
      pq_signature_schemes_enabled: true
    });
  });

  it("ACME and manual certificate are mutually exclusive (no cert when ACME on)", () => {
    const cfg = createHysteria2InboundConfigFromDraft(
      draft({
        certMode: "content",
        certificate: "CERT",
        key: "KEY",
        acmeEnabled: true,
        acmeDomain: ["his.example.com"],
        acmeEmail: "a@b.c",
        acmeProvider: "letsencrypt",
        acmeDns01Provider: "cloudflare",
        acmeDns01ApiToken: "tok123"
      })
    );
    expect("certificate" in cfg.tls).toBe(false);
    expect("key" in cfg.tls).toBe(false);
    expect(cfg.tls.acme).toEqual({
      domain: ["his.example.com"],
      email: "a@b.c",
      provider: "letsencrypt",
      dns01_challenge: { provider: "cloudflare", api_token: "tok123" }
    });
  });

  it("the schema accepts a masquerade object", () => {
    const cfg = {
      log: { level: "info" },
      inbounds: [createHysteria2InboundConfigFromDraft(draft({ masqueradeType: "proxy", masquerade: "https://a.example.com" }))],
      outbounds: [{ type: "direct" }]
    };
    const res = validateSingBoxCoreConfig(cfg);
    expect(res.ok).toBe(true);
  });

  it("flags an ACME inbound with no domain", () => {
    const issues = validateHysteria2InboundDraft(draft({ acmeEnabled: true, acmeDomain: [] }), 0, ["Hy2"]);
    expect(issues.some(i => i.path.endsWith("/acmeDomain"))).toBe(true);
  });

  it("flags a file masquerade with no directory", () => {
    const issues = validateHysteria2InboundDraft(draft({ masqueradeType: "file", masqueradeDirectory: "" }), 0, ["Hy2"]);
    expect(issues.some(i => i.path.endsWith("/masqueradeDirectory"))).toBe(true);
  });

  it("flags invalid masquerade headers JSON", () => {
    const issues = validateHysteria2InboundDraft(draft({ masqueradeType: "string", masqueradeHeaders: "not json" }), 0, ["Hy2"]);
    expect(issues.some(i => i.path.endsWith("/masqueradeHeaders"))).toBe(true);
  });
});
