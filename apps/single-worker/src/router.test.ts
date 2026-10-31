import {describe,it,expect} from "vitest";
import {classifyHostPath} from "./router";
const c="console.example.com",a="agent.example.com";
describe("single Worker dual-host security router",()=>{
 it("routes only the expected surface on each exact hostname",()=>{
  expect(classifyHostPath(c,"/",c,a)).toBe("control");
  expect(classifyHostPath(c,"/assets/app.js",c,a)).toBe("control");
  expect(classifyHostPath(c,"/api/v1/me",c,a)).toBe("control");
  expect(classifyHostPath(a,"/agent/v1/health",c,a)).toBe("agent");
  expect(classifyHostPath(a,"/agent/v1/ws",c,a)).toBe("agent");
  expect(classifyHostPath(a,"/agent/v1/report",c,a)).toBe("agent");
 });
 it("never exposes admin API or SPA via Agent hostname",()=>{
  for(const p of ["/","/index.html","/assets/index.js","/api/v1/me","/api/v1/health",
   "/api/v1/nodes","/anything","/agent","/agent/evil"]){
   expect(classifyHostPath(a,p,c,a),p).toBe("deny");
  }
 });
 it("never exposes Agent API from Control hostname",()=>{
  for(const p of ["/agent/v1/ws","/agent/v1/pair","/agent/v1/report","/agent/v1/health"]){
   expect(classifyHostPath(c,p,c,a),p).toBe("deny");
  }
 });
 it("denies random workers.dev, preview, hostname aliases and unknown hosts",()=>{
  for(const h of ["ssh-manager-staging.workers.dev","preview.console.example.com",
   "console.example.com.evil.org","agent.example.com.evil.org","unlisted.example.com"]){
   expect(classifyHostPath(h,"/api/v1/me",c,a)).toBe("deny");
   expect(classifyHostPath(h,"/agent/v1/ws",c,a)).toBe("deny");
  }
 });
 it("fails closed for missing, identical or wildcard domain variables",()=>{
  for(const [cHost,aHost] of [
   ["",a],[c,""],[c,c],["*.example.com",a],["http://example.com",a],
   [c,"agent.example.com/anything"],["REPLACE_CONTROL_HOSTNAME",a]
  ]){
   expect(classifyHostPath(c,"/api/v1/me",cHost,aHost)).toBe("misconfigured");
  }
 });
 it("rejects misleading aliases and prefixed Agent API paths",()=>{
  expect(classifyHostPath(a,"/agent/v1x/report",c,a)).toBe("deny");
  expect(classifyHostPath(a,"/agent/v1",c,a)).toBe("deny");
  expect(classifyHostPath(a,"/api/v1/me",c,a)).toBe("deny");
 });
});
