import React from "react";
import {renderToStaticMarkup} from "react-dom/server";
import {describe,expect,it} from "vitest";
import VerificationPanel from "./VerificationPanel";

const verification={
 node_id:"11111111-1111-4111-8111-111111111111",
 id:"22222222-2222-4222-8222-222222222222",
 status:"PENDING",token:"SECRET_CHALLENGE_MUST_NOT_CROSS_NODES",
 expires_at:1900000000,login_user:"root",fingerprint:"SHA256:test",
 prepared_at:null
};

describe("SSH verification UI is tied to the selected VPS",()=>{
 it("never shows another node's challenge token even if the previous network request completes late",()=>{
  const html=renderToStaticMarkup(<VerificationPanel nodeId="33333333-3333-4333-8333-333333333333"
   verification={verification} canManage busy={false} onCancel={()=>{}}/>);
  expect(html).toBe("");
 });
 it("shows a pending token only on the matching node",()=>{
  const html=renderToStaticMarkup(<VerificationPanel nodeId={verification.node_id}
   verification={verification} canManage busy={false} onCancel={()=>{}}/>);
  expect(html).toContain("SECRET_CHALLENGE_MUST_NOT_CROSS_NODES");
  expect(html).toContain("撤销本次挑战");
 });
 it("does not show an old token once challenge status is terminal",()=>{
  const html=renderToStaticMarkup(<VerificationPanel nodeId={verification.node_id}
   verification={{...verification,status:"VERIFIED"}} canManage busy={false} onCancel={()=>{}}/>);
  expect(html).not.toContain("SECRET_CHALLENGE_MUST_NOT_CROSS_NODES");
  expect(html).toContain("可信");
 });
 it("shows read-only status to Viewer and no cancellation action",()=>{
  const html=renderToStaticMarkup(<VerificationPanel nodeId={verification.node_id}
   verification={verification} canManage={false} busy={false} onCancel={()=>{}}/>);
  expect(html).not.toContain("撤销本次挑战");
 });
});
