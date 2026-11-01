import React from "react";
import {renderToStaticMarkup} from "react-dom/server";
import {describe,expect,it} from "vitest";
import NodeSecurityActions from "./NodeSecurityActions";
const props={online:true,busy:false,canManage:true,revisionReady:true,hasDailyKey:true,
 onPreflight:()=>{},onInspect:()=>{},onInstallDaily:()=>{}};
describe("SSH node actions are not available to Viewer or offline Agent",()=>{
 it("disables every operation button for Viewer",()=>{
  const html=renderToStaticMarkup(<NodeSecurityActions {...props} canManage={false}/>);
  expect(html.match(/<button/g)).toHaveLength(3);
  expect(html.match(/disabled=""/g)).toHaveLength(3);
 });
 it("disables every operation button when Agent heartbeat is stale/offline",()=>{
  const html=renderToStaticMarkup(<NodeSecurityActions {...props} online={false}/>);
  expect(html.match(/disabled=""/g)).toHaveLength(3);
 });
 it("requires verified revision and a configured daily key for installation",()=>{
  const html=renderToStaticMarkup(<NodeSecurityActions {...props} revisionReady={false}/>);
  expect(html.match(/disabled=""/g)).toHaveLength(1);
  expect(html).toContain("只读环境检查");
  expect(html).toContain("部署日常公钥");
 });
 it("enables all operations for an authorized, online, configured node",()=>{
  const html=renderToStaticMarkup(<NodeSecurityActions {...props}/>);
  expect(html).not.toContain("disabled=");
 });
});
