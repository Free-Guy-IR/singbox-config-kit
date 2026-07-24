# @pasarguard/singbox-config-kit

Browser-safe TypeScript helpers for generating and validating PasarGuard sing-box core
configuration JSON.

Scope (v1): only the `hysteria2` inbound type is supported, mirroring the panel's
`app/core/singbox.py::SingBoxConfig` backend, which only recognizes `hysteria2` inbounds.
A sing-box core config here is always a minimal server config:

```json
{
  "log": { "level": "info" },
  "inbounds": [ { "type": "hysteria2", "...": "..." } ],
  "outbounds": [ { "type": "direct" } ]
}
```

Modeled directly on the file layout and tooling of `@pasarguard/wireguard-config-kit`,
adapted for a **list** of Hysteria2 inbounds instead of a single flat interface object.

## Modules

- `types.ts` — plain config shape (`SingBoxCoreConfig`, `SingBoxHysteria2Inbound`, ...).
- `validation.ts` — Zod schema + semantic validators (`validateSingBoxCoreConfig`), kept
  compatible with the Python-side `SingBoxConfig._validate` / `_validate_hysteria2_inbound`
  rules: unique non-empty inbound tags, `listen_port` in `1..65535`, `tls.enabled === true`
  required on every hysteria2 inbound, at least one inbound and one outbound.
- `form.ts` — a "draft" shape for form state (`SingBoxCoreDraft`, `HysteriaInboundDraft`)
  distinct from the final JSON config, plus draft helpers used by the dashboard's visual
  editor (`createDefaultSingBoxCoreDraft`, `createDefaultHysteria2InboundDraft`,
  `validateSingBoxCoreDraft`, `createSingBoxCoreConfigFromDraft`,
  `generateSingBoxCoreConfigJsonFromDraft`).
- `core.ts` — pure config-building functions (`createHysteria2InboundConfig`,
  `createSingBoxCoreConfig`, `createSingBoxCorePayload`).

`users` on every hysteria2 inbound is always emitted as `[]` — the panel injects real
users into the running node config at sync time; this kit never represents or edits users.
