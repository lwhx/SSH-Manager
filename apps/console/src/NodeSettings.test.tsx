import React from "react";
import {renderToStaticMarkup} from "react-dom/server";
import {describe,it,expect} from "vitest";
import NodeSettings from "./NodeSettings";

const node={id:"a8fc10a0-7777-4d78-8e3a-2881e158b72c",name:"Production",ssh_host:"192.0.2.1",ssh_port:22,login_user:"root",status:"online",group_name:"prod",notes:""};
describe("node settings",()=>{
 it("renders connection properties read-only for paired nodes",()=>{
  const html=renderToStaticMarkup(<NodeSettings node={node} canEdit onSave={async()=>{}}/>);
  expect(html).toContain("节点名称");
  expect(html).toContain("分组");
  expect(html).toMatch(/<input(?=[^>]*name="ssh_host")(?=[^>]*disabled="")[^>]*>/);
  expect(html).toMatch(/<input(?=[^>]*name="ssh_port")(?=[^>]*disabled="")[^>]*>/);
  expect(html).toMatch(/<input(?=[^>]*name="login_user")(?=[^>]*disabled="")[^>]*>/);
 });
 it("permits editing unpaired connection properties only",()=>{
  const html=renderToStaticMarkup(<NodeSettings node={{...node,status:"unpaired"}} canEdit onSave={async()=>{}}/>);
  expect(html).toMatch(/<input(?=[^>]*name="ssh_host")(?=[^>]*value="192.0.2.1")[^>]*>/);
  expect(html).not.toMatch(/<input(?=[^>]*name="ssh_host")(?=[^>]*disabled="")[^>]*>/);
 });
 it("does not render submit actions for a viewer",()=>{
  const html=renderToStaticMarkup(<NodeSettings node={node} canEdit={false} onSave={async()=>{}}/>);
  expect(html).not.toContain('type="submit"');
 });
});
