package sshhelper

import (
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "testing"
 "time"
)

func TestRootSignedManualReceiptCannotBeForgedByAgent(t *testing.T){
 pub,key,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 h:=&Handler{ProofSigningKey:key,Clock:func()time.Time{return time.Unix(1000,0)}}
 cmd:=Command{V:1,ID:testOp,NodeID:testNode,Action:"ssh.rescue.enable",ExpectedRevision:"revision",
  IssuedAt:990,ExpiresAt:1030}
 detail:=map[string]any{"key_fingerprint":"SHA256:example","file_checked":true}
 result:=h.signManualReceipt(cmd,Result{OK:true,Code:"RESCUE_KEY_INSTALLED",Detail:detail})
 if !result.OK{t.Fatal("Root could not sign legitimate result")}
 wrapper:=result.Detail.(map[string]any)
 envelope:=wrapper["root_receipt"].(SignedManualReceipt)
 sig,err:=base64.RawURLEncoding.DecodeString(envelope.Signature);if err!=nil{t.Fatal(err)}
 if !ed25519.Verify(pub,[]byte(envelope.Payload),sig){t.Fatal("Root signature invalid")}
 raw,_:=json.Marshal(wrapper["result"])
 digest:=sha256.Sum256(raw)
 var parsed ManualOperationReceipt
 if err=json.Unmarshal([]byte(envelope.Payload),&parsed);err!=nil{t.Fatal(err)}
 if parsed.NodeID!=testNode||parsed.OperationID!=testOp||parsed.Action!=cmd.Action||
  parsed.DetailSHA256!=hex.EncodeToString(digest[:]){t.Fatal("Root receipt context mismatch")}
 forged:=[]byte(envelope.Payload+" ")
 if ed25519.Verify(pub,forged,sig){t.Fatal("Agent could rewrite receipt")}
}
func TestMissingRootSignerCannotProduceManualSuccess(t *testing.T){
 h:=&Handler{Clock:func()time.Time{return time.Unix(1000,0)}}
 cmd:=Command{ID:testOp,NodeID:testNode,Action:"ssh.password.disable",IssuedAt:990,ExpiresAt:1030}
 if got:=h.signManualReceipt(cmd,Result{OK:true,Code:"PASSWORD_DISABLED"});got.OK{
  t.Fatal("unsigned password change")
 }
}
