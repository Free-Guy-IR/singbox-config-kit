import type { CreateInboundOptions, CreateShadowsocksInboundOptions, CreateSingBoxCoreConfigOptions, CreateSingBoxCorePayloadOptions, CreateTuicInboundOptions, CreateHysteria2InboundOptions, CreateVlessInboundOptions, CreateVmessInboundOptions, CreateTrojanInboundOptions, SingBoxCoreConfig, SingBoxCorePayload, SingBoxHysteria2Inbound, SingBoxInbound } from "./types.js";
export declare function createVlessInboundConfig(options: CreateVlessInboundOptions): SingBoxInbound;
export declare function createVmessInboundConfig(options: CreateVmessInboundOptions): SingBoxInbound;
export declare function createTrojanInboundConfig(options: CreateTrojanInboundOptions): SingBoxInbound;
export declare function createShadowsocksInboundConfig(options: CreateShadowsocksInboundOptions): SingBoxInbound;
export declare function createTuicInboundConfig(options: CreateTuicInboundOptions): SingBoxInbound;
export declare function createHysteria2InboundConfig(options: CreateHysteria2InboundOptions): SingBoxHysteria2Inbound;
/** Dispatches to the per-protocol inbound builder based on the options' discriminant. */
export declare function createInboundConfig(options: CreateInboundOptions): SingBoxInbound;
export declare function createSingBoxCoreConfig(options: CreateSingBoxCoreConfigOptions): SingBoxCoreConfig;
export declare function generateSingBoxCoreConfigJson(options: CreateSingBoxCoreConfigOptions, space?: number): string;
export declare function createSingBoxCorePayload(options: CreateSingBoxCorePayloadOptions): SingBoxCorePayload;
//# sourceMappingURL=core.d.ts.map