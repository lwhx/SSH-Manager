package sshhelper

import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/json"
 "os/user"
 "path/filepath"
 "testing"

 "github.com/lwhx/SSH-Manager/agent/internal/sshkeys"
 "github.com/lwhx/SSH-Manager/agent/internal/sshmanaged"
 "github.com/lwhx/SSH-Manager/agent/internal/sshprobe"
)

type fakeManaged struct{ disables,restores int }
func (f *fakeManaged)Disable(ctx context.Context,node,user string,before sshprobe.Effective)(sshmanaged.Result,error){
 f.disables++
 return sshmanaged.Result{SnapshotRef:"a1b2c3d4e5f60718293a4b5c6d7e8f90",BeforeRevision:before.Revision,
  AfterRevision:"b123",ConfigHash:"a123",PasswordAuthentication:false,KeyboardInteractive:false},nil
}
func (f *fakeManaged)Restore(ctx context.Context,node,user,ref string,before sshprobe.Effective)(sshmanaged.Result,error){
 f.restores++
 return sshmanaged.Result{SnapshotRef:ref,BeforeRevision:before.Revision,AfterRevision:"back",PasswordAuthentication:true},nil
}
func manualCommand(t *testing.T,action,purpose string)Command{
 t.Helper()
 payload,_:=json.Marshal(ManualPayload{ConfirmNodeID:testNode,LoginUser:"root",
  Reason:"Operator explicitly approved this staging-only SSH action",
  VerificationID:"50000000-0000-4000-8000-000000000001",
  ProofID:"50000000-0000-4000-8000-000000000002",
  SnapshotRef:"a1b2c3d4e5f60718293a4b5c6d7e8f90",
  KeyID:testKeyID,
 })
 return Command{V:1,ID:testOp,NodeID:testNode,Action:action,
  Actor:"40000000-0000-4000-8000-000000000001",
  IssuedAt:990,ExpiresAt:1030,ExpectedRevision:"rev123",Payload:payload}
}
func TestManualPasswordDisableRequiresLocalOptInAndRootSigning(t *testing.T){
 priv,pub:=makeSigner(t)
 h,_:=newHandler(t,pub)
 f:=&fakeManaged{}
 h.Managed=f
 c:=manualCommand(t,"ssh.password.disable","password")
 if got:=h.Execute(context.Background(),signed(t,priv,c));got.OK||f.disables!=0{
  t.Fatal("password disabled without root signing key or local opt-in")
 }
 h2,_:=newHandler(t,pub)
 h2.Managed=f;h2.Config.EnablePasswordDisable=true
 if got:=h2.Execute(context.Background(),signed(t,priv,c));got.OK||f.disables!=0{
  t.Fatal("password disabled without Root private receipt signer")
 }
 h3,_:=newHandler(t,pub)
 pubRoot,rootPriv,err:=ed25519.GenerateKey(rand.Reader);_ = pubRoot
 if err!=nil{t.Fatal(err)}
 h3.Managed=f;h3.ProofSigningKey=rootPriv
 if got:=h3.Execute(context.Background(),signed(t,priv,c));got.OK||f.disables!=0{
  t.Fatal("password disabled without explicit local feature switch")
 }
 h4,_:=newHandler(t,pub)
 h4.Managed=f;h4.ProofSigningKey=rootPriv;h4.Config.EnablePasswordDisable=true
 got:=h4.Execute(context.Background(),signed(t,priv,c))
 if !got.OK||got.Code!="PASSWORD_DISABLED"||f.disables!=1{t.Fatalf("signed root operation failed %+v",got)}
 envelope:=got.Detail.(map[string]any)["root_receipt"].(SignedManualReceipt)
 if envelope.Payload==""||envelope.Signature==""{t.Fatal("no Root signed proof")}
}
func TestManualRescueCannotAffectAnotherNodeOrUnmanagedKey(t *testing.T){
 priv,pub:=makeSigner(t)
 _,rootPriv,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{t.Fatal(err)}
 key,fp:=makeKey(t)
 calls:=0
 makeH:=func()(*Handler,Command){
  h,_:=newHandler(t,pub)
  h.Config.EnableRescue=true
  h.ProofSigningKey=rootPriv
  h.Lookup=func(string)(*user.User,error){return &user.User{Username:"root",Uid:"0",Gid:"0",HomeDir:filepath.Join(t.TempDir(),"home")},nil}
  h.RescueInstall=func(string,int,int,string,string)(sshkeys.Result,error){
   calls++
   return sshkeys.Result{Fingerprint:fp,FileChecked:true,AlreadyPresent:true},nil
  }
  c:=manualCommand(t,"ssh.rescue.enable","rescue")
  c.Payload,_=json.Marshal(ManualPayload{ConfirmNodeID:testNode,LoginUser:"root",
   Reason:"Explicitly authorized on this selected test node",KeyID:testKeyID,
   PublicKey:key,Fingerprint:fp})
  return h,c
 }
 h,c:=makeH()
 var body ManualPayload
 _=json.Unmarshal(c.Payload,&body)
 body.ConfirmNodeID="00000000-0000-4000-8000-000000000001"
 c.Payload,_=json.Marshal(body)
 if got:=h.Execute(context.Background(),signed(t,priv,c));got.OK||calls!=0{
  t.Fatal("rescue activation accepted for another VPS")
 }
 h,c=makeH()
 if got:=h.Execute(context.Background(),signed(t,priv,c));got.OK||calls!=1{
  t.Fatalf("existing unmanaged authorized_keys falsely installed: %+v",got)
 }
}
