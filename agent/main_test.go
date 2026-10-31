package main
import (
 "crypto/ed25519"
 "crypto/rand"
 "encoding/json"
 "testing"
 "time"
)
func TestVerifyCommand(t *testing.T){
 pub,priv,_:=ed25519.GenerateKey(rand.Reader)
 _,device,_:=ed25519.GenerateKey(rand.Reader)
 a:=Agent{config:Config{NodeID:"00000000-0000-4000-8000-000000000001",CommandPublicKey:encode(pub)},secret:device}
 c:=Command{V:1,ID:"10000000-0000-4000-8000-000000000001",NodeID:a.config.NodeID,Action:"node.status",IssuedAt:time.Now().Unix(),ExpiresAt:time.Now().Add(time.Second*30).Unix()}
 raw,_:=json.Marshal(c)
 s:=SignedCommand{Command:string(raw),Signature:encode(ed25519.Sign(priv,raw))}
 if _,err:=a.verify(s);err!=nil{t.Fatal(err)}
 c.Action="shell.exec"
 raw,_=json.Marshal(c)
 s=SignedCommand{Command:string(raw),Signature:encode(ed25519.Sign(priv,raw))}
 if _,err:=a.verify(s);err==nil{t.Fatal("dangerous command accepted")}
 s.Signature="invalid"
 if _,err:=a.verify(s);err==nil{t.Fatal("invalid signature accepted")}
}
