package main

import (
 "crypto/ed25519"
 "crypto/rand"
 "encoding/json"
 "errors"
 "os"
 "path/filepath"
 "testing"
 "time"
)
func TestReceiptIsDurableAndRejectsReplay(t *testing.T){
 dir:=t.TempDir()
 a:=Agent{config:Config{StateDir:dir}}
 c:=Command{ID:"10000000-0000-4000-8000-000000000001",NodeID:"20000000-0000-4000-8000-000000000001",Action:"node.status"}
 if err:=a.claimOperation(c);err!=nil{t.Fatal(err)}
 if err:=a.claimOperation(c);!errors.Is(err,errAlreadyClaimed){t.Fatalf("expected duplicate, got %v",err)}
 if _,err:=os.Stat(filepath.Join(dir,"operations",c.ID+".json"));err!=nil{t.Fatal(err)}
 c.ID="../../passwd"
 if err:=a.claimOperation(c);err==nil{t.Fatal("accepted unsafe operation ID")}
}
func TestSignedCommandScopeAndExpiry(t *testing.T){
 pub,priv,_:=ed25519.GenerateKey(rand.Reader)
 id:="20000000-0000-4000-8000-000000000001"
 a:=Agent{config:Config{NodeID:id,CommandPublicKey:encode(pub),StateDir:t.TempDir()}}
 c:=Command{V:1,ID:"10000000-0000-4000-8000-000000000001",NodeID:id,Action:"node.status",IssuedAt:time.Now().Unix(),ExpiresAt:time.Now().Add(30*time.Second).Unix()}
 sign:=func()SignedCommand{raw,_:=json.Marshal(c);return SignedCommand{Command:string(raw),Signature:encode(ed25519.Sign(priv,raw))}}
 if _,err:=a.verify(sign());err!=nil{t.Fatal(err)}
 c.NodeID="30000000-0000-4000-8000-000000000001"
 if _,err:=a.verify(sign());err==nil{t.Fatal("accepted different node")}
 c.NodeID=id;c.ExpiresAt=time.Now().Add(-time.Second).Unix()
 if _,err:=a.verify(sign());err==nil{t.Fatal("accepted expired command")}
 c.ExpiresAt=time.Now().Add(30*time.Second).Unix();c.Action="shell.exec"
 if _,err:=a.verify(sign());err==nil{t.Fatal("accepted arbitrary shell command")}
}
