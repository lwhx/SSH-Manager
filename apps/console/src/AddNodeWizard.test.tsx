import React from "react";
import {renderToStaticMarkup} from "react-dom/server";
import {describe,it,expect} from "vitest";
import AddNodeWizard from "./AddNodeWizard";

describe("VPS registration wizard",()=>{
 const props={
  open:true,busy:false,revision:"a".repeat(40),gateway:"https://agent-staging.example.com",
  onClose:()=>{},onCreate:async()=>({node:{id:"00000000-0000-4000-8000-000000000001",name:"test",status:"unpaired",init_stage:"WAITING_PAIR"},pair:null}),
  onNewToken:async()=>({node_id:"00000000-0000-4000-8000-000000000001",token:"secret",expires_at:0}),
  onRefresh:async()=>({id:"00000000-0000-4000-8000-000000000001",name:"test",status:"unpaired",init_stage:"WAITING_PAIR"}),
  onOpenNode:()=>{}
 };
 it("starts in a standalone creation step",()=>{
  const html=renderToStaticMarkup(<AddNodeWizard {...props}/>);
  expect(html).toContain("基本信息");
  expect(html).toContain("安装 Agent");
  expect(html).toContain("确认连接");
  expect(html).toContain('role="dialog"');
  expect(html).not.toContain("secret");
 });
 it("renders nothing while closed",()=>{
  expect(renderToStaticMarkup(<AddNodeWizard {...props} open={false}/>)).toBe("");
 });
});
