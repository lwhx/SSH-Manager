import {describe,expect,it} from "vitest";
import {presentConsoleError} from "./errorPresentation";

describe("operator errors should not encourage an unsafe re-submit",()=>{
 it("describes an unknown SSH outcome as a locked, manual verification state",()=>{
  const message=presentConsoleError("NODE_OPERATION_RESULT_UNKNOWN");
  expect(message).toContain("结果未知");
  expect(message).toContain("禁止再次下发");
  expect(message).toContain("服务商控制台");
  expect(message).toContain("NODE_OPERATION_RESULT_UNKNOWN");
 });
 it("explains the current node already has a running command",()=>{
  const message=presentConsoleError("NODE_OPERATION_IN_PROGRESS");
  expect(message).toContain("已有任务");
  expect(message).toContain("不要重复");
 });
 it("explains concurrent metadata or pairing conflicts",()=>{
  const message=presentConsoleError("NODE_SETTINGS_CONFLICT");
  expect(message).toContain("Agent");
  expect(message).toContain("刷新");
  expect(message).toContain("409");
 });
 it("does not present offline or disabled high-risk operations as success",()=>{
  expect(presentConsoleError("NODE_OFFLINE")).toContain("离线");
  expect(presentConsoleError("MANUAL_SSH_FEATURE_DISABLED")).toContain("禁止");
  expect(presentConsoleError("INTERNAL_ERROR")).toContain("不要立即重复");
 });
 it("preserves unknown symbolic error codes for triage",()=>{
  expect(presentConsoleError("UNKNOWN_SERVER_ERROR")).toBe("UNKNOWN_SERVER_ERROR");
  expect(presentConsoleError(null)).toBe("REQUEST_FAILED");
 });
});
