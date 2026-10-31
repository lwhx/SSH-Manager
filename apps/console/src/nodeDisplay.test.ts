import {describe,expect,it} from "vitest";
import {filterNodes,isNodeOnline} from "./nodeDisplay";
const now=1_800_000_000;
const nodes=[
 {id:"a",name:"JP staging",ssh_host:"203.0.113.1",login_user:"root",status:"online",last_seen_at:now-20,init_stage:"PREFLIGHT",group_name:"test",created_at:3},
 {id:"b",name:"US prod",ssh_host:"198.51.100.9",login_user:"deploy",status:"online",last_seen_at:now-180,init_stage:"KEY_VERIFIED",group_name:"prod",created_at:2},
 {id:"c",name:"HK new",ssh_host:"192.0.2.8",login_user:"root",status:"unpaired",last_seen_at:null,init_stage:"WAITING_PAIR",group_name:"",created_at:1}
];
describe("VPS directory",()=>{
 it("marks a stale heartbeat as offline",()=>{
  expect(isNodeOnline(nodes[0],now)).toBe(true);
  expect(isNodeOnline(nodes[1],now)).toBe(false);
  expect(isNodeOnline(nodes[2],now)).toBe(false);
 });
 it("filters by status, group and multi-field search",()=>{
  expect(filterNodes(nodes,{status:"offline"},now).map(n=>n.id)).toEqual(["b"]);
  expect(filterNodes(nodes,{status:"unpaired"},now).map(n=>n.id)).toEqual(["c"]);
  expect(filterNodes(nodes,{group:"test",search:"203.0.113"},now).map(n=>n.id)).toEqual(["a"]);
  expect(filterNodes(nodes,{search:"DEPLOY"},now).map(n=>n.id)).toEqual(["b"]);
 });
 it("sorts deterministically by name or most recently added",()=>{
  expect(filterNodes(nodes,{sort:"name"},now).map(n=>n.id)).toEqual(["c","a","b"]);
  expect(filterNodes(nodes,{sort:"recent"},now).map(n=>n.id)).toEqual(["a","b","c"]);
 });
});