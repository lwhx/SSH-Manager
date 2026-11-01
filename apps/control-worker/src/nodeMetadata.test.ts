import {describe,expect,it} from "vitest";
import {parseNodeChanges,buildNodeSettingsUpdate,persistNodeSettingsUpdate} from "./nodeMetadata";
const n={name:"Existing",group_name:"",notes:"",ssh_host:"example.org",ssh_port:22,login_user:"root",status:"online"};
describe("audited node settings validation",()=>{
 it("updates metadata without touching SSH connection",()=>{
  const result=parseNodeChanges({name:"  New node  ",group_name:"  prod ",notes:"  checked "},n);
  expect(result).toMatchObject({name:"New node",group_name:"prod",notes:"checked",ssh_host:"example.org",ssh_port:22,login_user:"root"});
 });
 it("rejects sensitive SSH connection changes on paired nodes",()=>{
  for(const patch of [{ssh_host:"other.example"},{ssh_port:2222},{login_user:"another"}])
   expect(()=>parseNodeChanges(patch,n)).toThrow("PAIRED_NODE_CONNECTION_LOCKED");
 });
 it("allows valid changes to unpaired connection settings",()=>{
  expect(parseNodeChanges({ssh_host:"new.example.com",ssh_port:2222,login_user:"ubuntu"},{...n,status:"unpaired"})).toMatchObject({
   ssh_host:"new.example.com",ssh_port:2222,login_user:"ubuntu"
  });
 });
 it("rejects empty or unknown or invalid input",()=>{
  for(const patch of [{},{arbitrary:"value"},{name:""},{group_name:"a".repeat(81)},{notes:"x".repeat(2001)},{ssh_port:65536},{login_user:"root;evil"},{notes:"a\u0000b"}])
   expect(()=>parseNodeChanges(patch,n)).toThrow();
 });

 it("guards against pairing and stale concurrent node settings edits",()=>{
  const current={...n,status:"unpaired"};
  const changed=parseNodeChanges({name:"New name",ssh_host:"new.example.com",group_name:"prod"},current);
  const statement=buildNodeSettingsUpdate("00000000-0000-4000-8000-000000000001",current,changed);
  expect(statement.sql).toContain("WHERE id=? AND status=?");
  expect(statement.sql).toContain("AND name=? AND group_name=? AND notes=? AND ssh_host=? AND ssh_port=? AND login_user=?");
  expect(statement.sql).toContain("NOT EXISTS (SELECT 1 FROM agent_credentials");
  expect(statement.sql).toContain("revoked_at IS NULL");
  expect(statement.args.slice(0,6)).toEqual(["New name","prod","","new.example.com",22,"root"]);
  expect(statement.args[7]).toBe("unpaired");
  expect(statement.sql.split("?").length-1).toBe(statement.args.length);
 });
 it("allows metadata-only paired edits but rejects stale paired-state changes",()=>{
  const changed=parseNodeChanges({name:"Renamed",notes:"updated"},n);
  const statement=buildNodeSettingsUpdate("00000000-0000-4000-8000-000000000001",n,changed);
  expect(statement.sql).toContain("WHERE id=? AND status=?");
  expect(statement.sql).not.toContain("NOT EXISTS (SELECT 1 FROM agent_credentials");
  expect(statement.args[7]).toBe("online");
  expect(statement.args[8]).toBe("Existing");
 });
});
describe("node metadata updates and audit are atomic",()=>{
 const update={sql:"UPDATE nodes SET name=? WHERE id=? AND status=?",args:["Renamed","node-1","unpaired"]};
 function fixture(results:unknown[],failure?:Error){
  const batches:{sql:string;args:unknown[]}[][]=[];
  const db={
   prepare:(sql:string)=>({bind:(...args:unknown[])=>({sql,args})}),
   batch:async(statements:{sql:string;args:unknown[]}[])=>{
    batches.push(statements);
    if(failure)throw failure;
    return results;
   }
  } as unknown as D1Database;
  return {db,batches};
 }
 it("writes the optimistic update and its audit event in one D1 batch",async()=>{
  const f=fixture([{meta:{changes:1}},{meta:{changes:1}}]);
  await persistNodeSettingsUpdate(f.db,update,{
   auditId:"audit-1",actorId:"owner-1",nodeId:"node-1",createdAt:1800000000
  });
  expect(f.batches).toHaveLength(1);
  expect(f.batches[0]).toHaveLength(2);
  expect(f.batches[0][0]).toEqual({sql:update.sql,args:update.args});
  expect(f.batches[0][1].sql).toContain("INSERT INTO audit_logs");
  expect(f.batches[0][1].sql).toContain("WHERE changes()=1");
  expect(f.batches[0][1].args).toEqual(["audit-1","owner-1","node-1",1800000000]);
 });
 it("rejects a stale optimistic update without creating an audit record",async()=>{
  const f=fixture([{meta:{changes:0}},{meta:{changes:0}}]);
  await expect(persistNodeSettingsUpdate(f.db,update,{
   auditId:"audit-2",actorId:"owner-1",nodeId:"node-1",createdAt:1800000000
  })).rejects.toMatchObject({code:"NODE_SETTINGS_CONFLICT",httpStatus:409});
  expect(f.batches).toHaveLength(1);
 });
 it("propagates an audit transaction failure instead of reporting a saved node",async()=>{
  const failure=Error("AUDIT_WRITE_FAILED");
  const f=fixture([],failure);
  await expect(persistNodeSettingsUpdate(f.db,update,{
   auditId:"audit-3",actorId:"owner-1",nodeId:"node-1",createdAt:1800000000
  })).rejects.toBe(failure);
  expect(f.batches).toHaveLength(1);
 });
});
