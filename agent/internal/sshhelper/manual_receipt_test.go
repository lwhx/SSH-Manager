package sshhelper

import (
 "context"
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

func TestManualPrewriteFailureHasIndependentRootNoWriteReceipt(t *testing.T){
 signer,pub:=makeSigner(t)
 rootPub,rootPriv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 h,_:=newHandler(t,pub)
 h.ProofSigningKey=rootPriv
 h.Config.EnablePasswordDisable=true
 f:=&fakeManaged{}
 h.Managed=f
 cmd:=manualCommand(t,"ssh.password.disable","password")
 var wrong ManualPayload
 if err=json.Unmarshal(cmd.Payload,&wrong);err!=nil{t.Fatal(err)}
 wrong.ConfirmNodeID="00000000-0000-4000-8000-000000000001"
 cmd.Payload,_=json.Marshal(wrong)
 result:=h.Execute(context.Background(),signed(t,signer,cmd))
 if result.OK||result.Code!="MANUAL_NODE_CONFIRMATION_REQUIRED"||f.disables!=0{
  t.Fatalf("prewrite guard was bypassed: %+v disables=%d",result,f.disables)
 }
 detail,ok:=result.Detail.(map[string]any);if !ok{t.Fatalf("no signed Root failure detail: %+v",result)}
 signedProof,ok:=detail["root_receipt"].(SignedManualReceipt);if !ok{t.Fatalf("no Root failure signature: %+v",detail)}
 signature,err:=base64.RawURLEncoding.DecodeString(signedProof.Signature);if err!=nil{t.Fatal(err)}
 if !ed25519.Verify(rootPub,[]byte(signedProof.Payload),signature){t.Fatal("failure receipt not signed by Root")}
 var receipt map[string]any
 if err=json.Unmarshal([]byte(signedProof.Payload),&receipt);err!=nil{t.Fatal(err)}
 if receipt["no_ssh_write"]!=true||receipt["result_code"]!=result.Code||receipt["operation_id"]!=cmd.ID{
  t.Fatalf("Root negative receipt does not attest no SSH write: %+v",receipt)
 }
}
func TestRootNeverSignsNoWriteForAmbiguousSSHFailure(t *testing.T){
 _,key,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 h:=&Handler{ProofSigningKey:key,Clock:func()time.Time{return time.Unix(1000,0)}}
 cmd:=Command{ID:testOp,NodeID:testNode,Action:"ssh.password.disable",IssuedAt:990,ExpiresAt:1030}
 result:=h.signManualReceipt(cmd,Result{Code:"PASSWORD_DISABLE_MANUAL_REVIEW"})
 if result.OK{t.Fatal("ambiguous write marked as a successful action")}
 if detail,ok:=result.Detail.(map[string]any);ok{
  if _,signed:=detail["root_receipt"];signed{t.Fatal("ambiguous SSH write received a no-write Root receipt")}
 }
}
