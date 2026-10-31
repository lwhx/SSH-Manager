import React from "react";
import {renderToStaticMarkup} from "react-dom/server";
import {describe,expect,it} from "vitest";
import NodeOperationStatus from "./NodeOperationStatus";

const operation={id:"22222222-2222-4222-8222-222222222222",node_id:"11111111-1111-4111-8111-111111111111"};
describe("Node operation result belongs only to its VPS",()=>{
 it("does not show an old node's result after switching VPS",()=>{
  const html=renderToStaticMarkup(<NodeOperationStatus nodeId="33333333-3333-4333-8333-333333333333"
   operation={operation} result={{status:"RESULT_UNKNOWN",detail:"OTHER_NODE_SECRET"}}/>);
  expect(html).toBe("");
 });
 it("shows uncertainty, not success, on the correct node",()=>{
  const html=renderToStaticMarkup(<NodeOperationStatus nodeId={operation.node_id}
   operation={operation} result={{status:"RESULT_UNKNOWN",result_code:"TIMEOUT",detail:"manual review required"}}/>);
  expect(html).toContain("结果未知");
  expect(html).toContain("TIMEOUT");
  expect(html).not.toContain("已成功");
 });
 it("shows a pending message before the Agent reports status",()=>{
  const html=renderToStaticMarkup(<NodeOperationStatus nodeId={operation.node_id}
   operation={operation} result={null}/>);
  expect(html).toContain("等待 Agent");
 });
});
