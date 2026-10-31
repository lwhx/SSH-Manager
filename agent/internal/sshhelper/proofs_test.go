package sshhelper

import(
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "errors"
 "os"
 "os/user"
 "path/filepath"
 "strings"
 "testing"
 "time"

 "github.com/lwhx/SSH-Manager/agent/internal/sshproof"
 "github.com/lwhx/SSH-Manager/agent/internal/sshprobe"
)

func TestRootProofSessionSignedAndConsumedOnce(t *testing.T){
 if os.Geteuid()!=0{t.Skip("root-only cryptographic proof integration fixture")}
 now:=time.Now().UTC()
 nonceBytes:=make([]byte,32)
 if _,err:=rand.Read(nonceBytes);err!=nil{t.Fatal(err)}
 nonce:=base64.RawURLEncoding.EncodeToString(nonceBytes)
 sum:=sha256.Sum256([]byte(nonce))
 rev:=strings.Repeat("a",64)
 challenge:=PreparedChallenge{
  VerificationID:"10000000-0000-4000-8000-000000000001",
  KeyID:"20000000-0000-4000-8000-000000000001",
  LoginUser:"root",Fingerprint:"SHA256:WqyC1TNJwaA73QFZwyV9a7G2SpMUEMDwVZ7OEWHsMmg",
  ConfigRevision:rev,NonceHash:hex.EncodeToString(sum[:]),
  IssuedAt:now.Unix()-10,ExpiresAt:now.Unix()+150,
 }
 base:=t.TempDir()
 ch:=&ChallengeStore{Directory:filepath.Join(base,"challenges")}
 if err:=ch.Save(challenge);err!=nil{t.Fatal(err)}
 out:=&Outbox{Directory:filepath.Join(base,"outbox")}
 if err:=os.Mkdir(out.Directory,0700);err!=nil{t.Fatal(err)}
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 h:=&Handler{
  Config:Config{NodeID:"30000000-0000-4000-8000-000000000001",
    CommandPublicKey:base64.RawURLEncoding.EncodeToString(pub),
    AllowedUser:"root",EnableSSHProof:true,
    ClientAddress:"203.0.113.9",LocalAddress:"192.0.2.20",
    SSHPort:22,SnapshotRoot:filepath.Join(base,"snapshots")},
  ProofSigningKey:priv,Challenges:ch,Outbox:out,
  Clock:time.Now,EUID:os.Geteuid,
  Lookup:func(string)(*user.User,error){return &user.User{Username:"root",Uid:"0",Gid:"0"},nil},
  Inspect:func(context.Context,Config)(sshprobe.Effective,error){
   return sshprobe.Effective{Revision:rev,PublicKeyAuthentication:true,
    AuthorizedKeysFile:[]string{".ssh/authorized_keys"},
    PermitRootLogin:"prohibit-password",AuthenticationMethods:"any"},nil
  },
  ObserveSSH:func(context.Context,int,sshproof.Challenge,sshproof.ProcessReader)(sshproof.Event,error){
   return sshproof.Event{
    User:"root",Fingerprint:challenge.Fingerprint,ClientIP:"203.0.113.9",ClientPort:52440,
    PID:100,SourcePath:"/usr/sbin/sshd",Timestamp:time.Now().UTC(),
   },nil
  },
  ProcessReader:func(pid int)(sshproof.ProcState,error){
   switch pid{
   case 300:return sshproof.ProcState{PID:300,PPID:200,RealUID:0,Executable:"/usr/bin/ssh-manager-prove"},nil
   case 200:return sshproof.ProcState{PID:200,PPID:100,RealUID:0,Executable:"/bin/sh"},nil
   case 100:return sshproof.ProcState{PID:100,PPID:1,RealUID:0,Executable:"/usr/sbin/sshd"},nil
   }
   return sshproof.ProcState{},errors.New("untrusted process")
  },
 }
 request:=ProofRequest{VerificationID:challenge.VerificationID,Nonce:"not-an-actual-verification-token"}
 if result:=h.ProveSession(context.Background(),300,0,request);result.OK{
  t.Fatal("forged nonce accepted")
 }
 request.Nonce=nonce
 if result:=h.ProveSession(context.Background(),300,1000,request);result.OK{
  t.Fatal("different local UID accepted")
 }
 result:=h.ProveSession(context.Background(),300,0,request)
 if !result.OK||result.Code!="SIGNED_PROOF_QUEUED"{
  t.Fatalf("root SSH proof not signed: %+v",result)
 }
 signed,err:=out.Peek();if err!=nil{t.Fatal(err)}
 att,err:=sshproof.VerifyAttestation(signed,pub)
 if err!=nil||att.NodeID!=h.Config.NodeID||att.VerificationID!=challenge.VerificationID||
  att.ClientPort!=52440||att.NonceHash!=challenge.NonceHash{
  t.Fatalf("signed server proof context mismatch: %+v %v",att,err)
 }
 if result=h.ProveSession(context.Background(),300,0,request);result.OK{
  t.Fatal("same verification challenge signed twice")
 }
 if err:=out.Ack(att.ProofID);err!=nil{t.Fatal(err)}
 if _,err=out.Peek();!errors.Is(err,os.ErrNotExist){t.Fatal("root proof ack did not clear outbox")}
}
