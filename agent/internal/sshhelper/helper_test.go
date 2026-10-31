package sshhelper

import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/base64"
 "encoding/binary"
 "encoding/json"
 "errors"
 "os"
 "os/user"
 "path/filepath"
 "testing"
 "time"

 "github.com/lwhx/SSH-Manager/agent/internal/sshkeys"
 "github.com/lwhx/SSH-Manager/agent/internal/sshprobe"
)
const testNode="10000000-0000-4000-8000-000000000001"
const testOp="20000000-0000-4000-8000-000000000001"
const testKeyID="30000000-0000-4000-8000-000000000001"
func makeSigner(t *testing.T)(ed25519.PrivateKey,string){
 t.Helper()
 public,private,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{t.Fatal(err)}
 return private,base64.RawURLEncoding.EncodeToString(public)
}
func newHandler(t *testing.T,signerKey string)(*Handler,*int){
 t.Helper()
 calls:=new(int)
 h:=&Handler{
  Config:Config{NodeID:testNode,CommandPublicKey:signerKey,AllowedUser:"root",ClientAddress:"192.0.2.10",LocalAddress:"192.0.2.20",SSHPort:22,SnapshotRoot:filepath.Join(t.TempDir(),"snaps"),EnableDailyInstall:true},
  Journal:&Journal{Directory:filepath.Join(t.TempDir(),"journal")},
  Clock:func()time.Time{return time.Unix(1000,0)},
  EUID:func()int{return 0},
  Lookup:func(name string)(*user.User,error){return &user.User{Username:"root",Uid:"0",Gid:"0",HomeDir:"/root"},nil},
  Inspect:func(context.Context,Config)(sshprobe.Effective,error){
   return sshprobe.Effective{PublicKeyAuthentication:true,AuthorizedKeysFile:[]string{".ssh/authorized_keys"},PermitRootLogin:"prohibit-password",AuthenticationMethods:"any",Revision:"rev123"},nil
  },
  Install:func(home string,uid,gid int,key,snapshot string)(sshkeys.Result,error){
   *calls++
   _,fp,err:=sshkeys.NormalizeED25519(key)
   if err!=nil{return sshkeys.Result{},err}
   return sshkeys.Result{FileChecked:true,Fingerprint:fp,SnapshotRef:"test"},nil
  },
 }
 return h,calls
}
func makeKey(t *testing.T)(string,string){
 t.Helper()
 pub,_,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{t.Fatal(err)}
 buf:=make([]byte,51)
 binary.BigEndian.PutUint32(buf[0:4],11)
 copy(buf[4:15],[]byte("ssh-ed25519"))
 binary.BigEndian.PutUint32(buf[15:19],32)
 copy(buf[19:],pub)
 value:="ssh-ed25519 "+base64.StdEncoding.EncodeToString(buf)
 _,fingerprint,err:=sshkeys.NormalizeED25519(value)
 if err!=nil{t.Fatal(err)}
 return value,fingerprint
}
func signed(t *testing.T,key ed25519.PrivateKey,c Command)SignedCommand{
 t.Helper()
 raw,err:=json.Marshal(c)
 if err!=nil{t.Fatal(err)}
 return SignedCommand{Command:string(raw),Signature:base64.RawURLEncoding.EncodeToString(ed25519.Sign(key,raw))}
}
func validCommand(t *testing.T)Command{
 pub,fp:=makeKey(t)
 payload,_:=json.Marshal(KeyPayload{LoginUser:"root",PublicKey:pub,Fingerprint:fp,KeyID:testKeyID})
 return Command{V:1,ID:testOp,NodeID:testNode,Action:"ssh.daily.install",Actor:"owner",IssuedAt:990,ExpiresAt:1030,ExpectedRevision:"rev123",Payload:payload}
}
func TestSignedDailyInstallAndReplay(t *testing.T){
 key,pub:=makeSigner(t)
 h,calls:=newHandler(t,pub)
 s:=signed(t,key,validCommand(t))
 got:=h.Execute(context.Background(),s)
 if !got.OK||got.Code!="DAILY_KEY_WRITTEN_AWAITING_LOGIN_PROOF"{t.Fatalf("unexpected result: %+v",got)}
 if *calls!=1{t.Fatal("installer was not called once")}
 again:=h.Execute(context.Background(),s)
 if again.OK||*calls!=1{t.Fatal("replayed operation")}
}
func TestFailClosedPolicies(t *testing.T){
 key,pub:=makeSigner(t)
 cases:=[]struct{
  name string
  change func(*Handler,*Command)
 }{
  {"disabled",func(h *Handler,c *Command){h.Config.EnableDailyInstall=false}},
  {"revision-mismatch",func(h *Handler,c *Command){c.ExpectedRevision="unverified"}},
  {"node-scope",func(h *Handler,c *Command){c.NodeID="00000000-0000-4000-8000-000000000000"}},
  {"other-user",func(h *Handler,c *Command){var p KeyPayload;_ = json.Unmarshal(c.Payload,&p);p.LoginUser="other";c.Payload,_=json.Marshal(p)}},
  {"unsupported-action",func(h *Handler,c *Command){c.Action="ssh.password.disable"}},
  {"stale",func(h *Handler,c *Command){c.ExpiresAt=900}},
  {"future",func(h *Handler,c *Command){c.IssuedAt=2000;c.ExpiresAt=2030}},
  {"not-root",func(h *Handler,c *Command){h.EUID=func()int{return 1001}}},
  {"bad-policy",func(h *Handler,c *Command){h.Inspect=func(context.Context,Config)(sshprobe.Effective,error){return sshprobe.Effective{},errors.New("sshd failure")}}},
 }
 for _,tc:=range cases{
  t.Run(tc.name,func(t *testing.T){
   h,calls:=newHandler(t,pub)
   c:=validCommand(t);tc.change(h,&c)
   got:=h.Execute(context.Background(),signed(t,key,c))
   if got.OK||*calls!=0{t.Fatalf("unsafe command succeeded: %+v",got)}
  })
 }
}
func TestTamperedSignatureNeverRuns(t *testing.T){
 key,pub:=makeSigner(t)
 h,calls:=newHandler(t,pub)
 s:=signed(t,key,validCommand(t))
 s.Command+=" "
 got:=h.Execute(context.Background(),s)
 if got.OK||*calls!=0{t.Fatalf("modified command accepted: %+v",got)}
}
func TestRootJournalPersists(t *testing.T){
 journal:=&Journal{Directory:filepath.Join(t.TempDir(),"journal")}
 if err:=journal.Claim(testOp,testNode,"ssh.policy.inspect");err!=nil{t.Fatal(err)}
 if err:=(&Journal{Directory:journal.Directory}).Claim(testOp,testNode,"ssh.policy.inspect");err==nil{t.Fatal("replay across journal processes")}
 if _,err:=os.Stat(filepath.Join(journal.Directory,testOp+".json"));err!=nil{t.Fatal(err)}
 if err:=journal.Claim("../../root",testNode,"ssh.policy.inspect");err==nil{t.Fatal("path traversal accepted")}
}
func TestPolicyConfigurationChecks(t *testing.T){
 _,pub:=makeSigner(t)
 h,_:=newHandler(t,pub)
 if err:=h.Config.Validate();err!=nil{t.Fatal(err)}
 h.Config.ClientAddress="not-an-ip"
 if err:=h.Config.Validate();err==nil{t.Fatal("invalid IP accepted")}
 h.Config.ClientAddress="192.0.2.10"
 h.Config.SnapshotRoot="/"
 if err:=h.Config.Validate();err==nil{t.Fatal("unsafe snapshot root accepted")}
}


func TestSignedVerificationPrepareCannotVerifySSHOrChangePassword(t *testing.T){
 signer,pub:=makeSigner(t)
 h,calls:=newHandler(t,pub)
 prepared:=preparedFixture()
 h.Config.EnableDailyInstall=false
 h.Challenges=&ChallengeStore{Directory:filepath.Join(t.TempDir(),"challenges")}
 h.Inspect=func(context.Context,Config)(sshprobe.Effective,error){
  return sshprobe.Effective{
   PublicKeyAuthentication:true,
   AuthorizedKeysFile:[]string{".ssh/authorized_keys"},
   PermitRootLogin:"prohibit-password",
   AuthenticationMethods:"any",Revision:prepared.ConfigRevision,
  },nil
 }
 payload,_:=json.Marshal(prepared)
 c:=Command{
  V:1,ID:"60000000-0000-4000-8000-000000000001",NodeID:testNode,
  Action:"ssh.verification.prepare",Actor:"owner",IssuedAt:990,ExpiresAt:1030,
  ExpectedRevision:prepared.ConfigRevision,Payload:payload,
 }
 result:=h.Execute(context.Background(),signed(t,signer,c))
 if !result.OK||result.Code!="VERIFICATION_PREPARED"{
  t.Fatalf("failed to prepare signed challenge: %+v",result)
 }
 if *calls!=0{t.Fatal("verification preparation wrote SSH keys")}
 saved,err:=h.Challenges.Read(prepared.VerificationID)
 if err!=nil||saved.NonceHash!=prepared.NonceHash{t.Fatalf("missing prepared challenge: %v",err)}
 if repeated:=h.Execute(context.Background(),signed(t,signer,c));repeated.OK{
  t.Fatal("same signed verification preparation executed twice")
 }
}
func TestRejectsMismatchedSignedPreparation(t *testing.T){
 signer,pub:=makeSigner(t)
 h,_:=newHandler(t,pub)
 prepared:=preparedFixture()
 h.Config.EnableDailyInstall=false
 h.Challenges=&ChallengeStore{Directory:filepath.Join(t.TempDir(),"challenges")}
 h.Inspect=func(context.Context,Config)(sshprobe.Effective,error){
  return sshprobe.Effective{
   PublicKeyAuthentication:true,
   AuthorizedKeysFile:[]string{".ssh/authorized_keys"},
   PermitRootLogin:"prohibit-password",AuthenticationMethods:"any",Revision:prepared.ConfigRevision,
  },nil
 }
 prepared.LoginUser="other"
 payload,_:=json.Marshal(prepared)
 c:=Command{
  V:1,ID:"60000000-0000-4000-8000-000000000002",NodeID:testNode,
  Action:"ssh.verification.prepare",Actor:"owner",IssuedAt:990,ExpiresAt:1030,
  ExpectedRevision:prepared.ConfigRevision,Payload:payload,
 }
 result:=h.Execute(context.Background(),signed(t,signer,c))
 if result.OK{t.Fatal("accepted root challenge for the wrong Linux user")}
}


func TestRootHelperDurablyFinalizesBeforeReturningAndNeverReexecutes(t *testing.T){
 private,pub:=makeSigner(t)
 h,calls:=newHandler(t,pub)
 c:=validCommand(t)
 c.Action="ssh.policy.inspect"
 c.ExpectedRevision="unverified"
 original:=h.Execute(context.Background(),signed(t,private,c))
 if !original.OK||original.Code!="POLICY_INSPECTED"{t.Fatalf("inspect not completed: %+v",original)}
 recovered,err:=(&Journal{Directory:h.Journal.Directory}).Recover(c.ID,testNode,c.Action)
 if err!=nil||recovered.State!="RECORDED"||!recovered.Result.OK||
  recovered.Result.Code!=original.Code{
  t.Fatalf("root crash recovery did not find durable result: %+v %v",recovered,err)
 }
 if *calls!=0{t.Fatal("recovery must not install an SSH key")}
 if again:=h.Execute(context.Background(),signed(t,private,c));again.OK{
  t.Fatal("replayed signed Root operation executed after durable completion")
 }
 wrongNode,err:=h.Journal.Recover(c.ID,"40000000-0000-4000-8000-000000000001",c.Action)
 if err==nil||wrongNode.State=="RECORDED"{t.Fatal("wrong node recovered Root result")}
 wrongAction,err:=h.Journal.Recover(c.ID,testNode,"ssh.daily.install")
 if err==nil||wrongAction.State=="RECORDED"{t.Fatal("wrong SSH action recovered root result")}
}
func TestRootJournalReservedWithoutOutcomeRequiresManualReview(t *testing.T){
 j:=&Journal{Directory:filepath.Join(t.TempDir(),"journal")}
 if err:=j.Claim(testOp,testNode,"ssh.daily.install");err!=nil{t.Fatal(err)}
 recovery,err:=j.Recover(testOp,testNode,"ssh.daily.install")
 if err!=nil||recovery.State!="UNCONFIRMED"||recovery.Result.OK{
  t.Fatalf("unsafe optimistic recovery of unfinished SSH key install: %+v %v",recovery,err)
 }
 if err:=j.Finalize(testOp,testNode,"ssh.daily.install",Result{
  OK:true,Code:"DAILY_KEY_WRITTEN_AWAITING_LOGIN_PROOF",
 });err!=nil{t.Fatal(err)}
 recovery,err=j.Recover(testOp,testNode,"ssh.daily.install")
 if err!=nil||recovery.State!="RECORDED"||!recovery.Result.OK{t.Fatal("root outcome not durable")}
 if err:=j.Finalize(testOp,testNode,"ssh.daily.install",Result{
  OK:false,Code:"KEY_INSTALL_FAILED",
 });err==nil{t.Fatal("Root result replaced after finalization")}
}
