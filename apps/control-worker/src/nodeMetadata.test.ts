import {describe,expect,it} from "vitest";
import {parseNodeChanges} from "./nodeMetadata";
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
});