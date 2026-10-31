import {describe,expect,it} from "vitest";
import {consoleRouteHref,parseConsoleRoute} from "./nodeNavigation";
const id="b8787344-6ad7-4812-8526-051d59caf9c3";
describe("SSH Manager console navigation",()=>{
 it("keeps a shareable, exact single-node route",()=>{
  expect(consoleRouteHref("nodes",id)).toBe("#/nodes/"+id);
  expect(parseConsoleRoute("#/nodes/"+id)).toEqual({page:"nodes",nodeId:id});
 });
 it("supports all independent admin sections",()=>{
  for(const page of ["dashboard","nodes","keys","tasks","audit","settings"] as const)
   expect(parseConsoleRoute(consoleRouteHref(page))).toEqual({page,nodeId:null});
 });
 it("rejects malformed routes without selecting any VPS",()=>{
  expect(parseConsoleRoute("#/nodes/../../secrets")).toEqual({page:"nodes",nodeId:null});
  expect(parseConsoleRoute("#/nodes/not-a-uuid")).toEqual({page:"nodes",nodeId:null});
  expect(parseConsoleRoute("#/unknown")).toEqual({page:"dashboard",nodeId:null});
  expect(parseConsoleRoute("#")).toEqual({page:"dashboard",nodeId:null});
 });
});