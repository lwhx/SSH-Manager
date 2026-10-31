package main

import (
 "crypto/ed25519"
 "crypto/rand"
 "encoding/json"
 "os"
 "path/filepath"
 "testing"
)
func pairedTestConfig(t *testing.T)Config{
 t.Helper()
 pub,_ ,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 _,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 return Config{
  Gateway:"https://example.test",
  NodeID:"10000000-0000-4000-8000-000000000001",
  DeviceKey:encode(priv),CommandPublicKey:encode(pub),
 }
}
func TestPairingStoresRuntimeSocketAndPersistentReceiptDir(t *testing.T){
 c:=pairedTestConfig(t)
 path:=filepath.Join(t.TempDir(),"agent.json")
 if err:=savePairingConfig(path,c);err!=nil{t.Fatal(err)}
 data,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
 var onDisk Config
 if err=json.Unmarshal(data,&onDisk);err!=nil{t.Fatal(err)}
 if onDisk.HelperSocket!=defaultAgentHelperSocket||onDisk.StateDir!=defaultAgentStateDir{
  t.Fatalf("pairing did not store usable root Helper and state directories: %+v",onDisk)
 }
 if stat,err:=os.Stat(path);err!=nil||stat.Mode().Perm()!=0600{
  t.Fatalf("Agent private config permissions are unsafe: %v %v",stat,err)
 }
 read,key,err:=readConfig(path)
 if err!=nil||len(key)!=ed25519.PrivateKeySize||read.HelperSocket!=defaultAgentHelperSocket{
  t.Fatalf("paired Agent cannot reload its config: %v",err)
 }
 if err:=savePairingConfig(path,c);err==nil{
  t.Fatal("pairing overwrote existing credentials")
 }
}
func TestLegacyPairingAndUnsafeConfigFailClosed(t *testing.T){
 c:=pairedTestConfig(t)
 if err:=normalizeAgentConfig(&c);err!=nil{t.Fatal(err)}
 if c.StateDir!=defaultAgentStateDir||c.HelperSocket!=defaultAgentHelperSocket{
  t.Fatal("legacy empty config was not upgraded safely")
 }
 for _,alter:=range []func(*Config){
  func(c *Config){c.HelperSocket="/tmp/fake.sock"},
  func(c *Config){c.StateDir="../../tmp"},
  func(c *Config){c.StateDir="/"},
  func(c *Config){c.Gateway="http://example.test"},
  func(c *Config){c.Gateway="https://u:p@example.test"},
  func(c *Config){c.Gateway="https://example.test/evil"},
  func(c *Config){c.NodeID="../../other"},
 }{
  changed:=pairedTestConfig(t);alter(&changed)
  if err:=normalizeAgentConfig(&changed);err==nil{
   t.Fatalf("unsafe Agent configuration accepted: %+v",changed)
  }
 }
}
func TestRejectsWorldReadableAndSymlinkDeviceKeys(t *testing.T){
 c:=pairedTestConfig(t)
 path:=filepath.Join(t.TempDir(),"agent.json")
 if err:=savePairingConfig(path,c);err!=nil{t.Fatal(err)}
 link:=filepath.Join(filepath.Dir(path),"aliased.json")
 if err:=os.Symlink(path,link);err!=nil{t.Fatal(err)}
 if _,_,err:=readConfig(link);err==nil{t.Fatal("Agent read a symlinked credential")}
 if err:=os.Chmod(path,0644);err!=nil{t.Fatal(err)}
 if _,_,err:=readConfig(path);err==nil{t.Fatal("Agent read a world-readable private key")}
}
