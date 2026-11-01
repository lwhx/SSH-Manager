import {describe,it,expect} from "vitest";
import {operationStatusPresentation} from "./operationPresentation";

describe("operation status presentation",()=>{
 it("treats an unknown execution result as a danger, not success",()=>{
  expect(operationStatusPresentation("RESULT_UNKNOWN")).toEqual({
   label:"结果未知 · 请核查 VPS",tone:"danger",terminal:false
  });
 });
 it("shows success only for signed successful operations",()=>{
  expect(operationStatusPresentation("SUCCEEDED")).toEqual({label:"已成功",tone:"success",terminal:true});
  expect(operationStatusPresentation("FAILED").tone).toBe("danger");
  expect(operationStatusPresentation("RUNNING").tone).toBe("neutral");
  expect(operationStatusPresentation("EXPIRED").tone).toBe("danger");
 });
});
