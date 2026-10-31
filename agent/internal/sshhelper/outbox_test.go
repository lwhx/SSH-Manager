package sshhelper

import (
 "crypto/ed25519"
 "crypto/rand"
 "encoding/json"
 "errors"
 "os"
 "path/filepath"
 "testing"

 "github.com/lwhx/SSH-Manager/agent/internal/sshproof"
)

func TestRootQuarantineKeepsRejectedProofAndUnblocksFollowingProof(t *testing.T){
 if os.Geteuid()!=0{t.Skip("root-owned proof outbox test")}
 dir:=filepath.Join(t.TempDir(),"root-outbox")
 if err:=os.Mkdir(dir,0700);err!=nil{t.Fatal(err)}
 out:=&Outbox{Directory:dir}
 public,private,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{t.Fatal(err)}
 firstID:="10000000-0000-4000-8000-000000000001"
 secondID:="20000000-0000-4000-8000-000000000001"
 for _,id:=range []string{firstID,secondID}{
  signed,signErr:=sshproof.SignAttestation(sshproof.Attestation{
   Version:1,ProofID:id,NodeID:"30000000-0000-4000-8000-000000000001",
  },private)
  if signErr!=nil{t.Fatal(signErr)}
  if err=out.Save(id,signed);err!=nil{t.Fatal(err)}
 }
 if err:=out.Quarantine(firstID,"CHALLENGE_NOT_ACTIVE");err!=nil{t.Fatal(err)}
 if _,err:=os.Stat(filepath.Join(dir,firstID+".json"));!errors.Is(err,os.ErrNotExist){
  t.Fatal("terminally rejected proof still blocks front of queue")
 }
 raw,err:=os.ReadFile(filepath.Join(dir,"rejected",firstID+".json"))
 if err!=nil{t.Fatal(err)}
 var preserved sshproof.SignedAttestation
 if err=json.Unmarshal(raw,&preserved);err!=nil{t.Fatal(err)}
 valid,err:=sshproof.VerifyAttestation(preserved,public)
 if err!=nil||valid.ProofID!=firstID{t.Fatal("root-only rejected proof must preserve signed evidence")}
 reason,err:=os.ReadFile(filepath.Join(dir,"rejected",firstID+".reason"))
 if err!=nil||string(reason)!="CHALLENGE_NOT_ACTIVE\n"{t.Fatal("archive did not persist rejection reason")}
 if st,err:=os.Stat(filepath.Join(dir,"rejected"));err!=nil||st.Mode().Perm()!=0700{
  t.Fatal("rejected-proof directory not root private")
 }
 next,err:=out.Peek()
 if err!=nil{t.Fatal(err)}
 parsed,err:=sshproof.VerifyAttestation(next,public)
 if err!=nil||parsed.ProofID!=secondID{
  t.Fatal("invalid old proof blocked the next newly signed proof")
 }
 if err=out.Quarantine(secondID,"NETWORK_TIMEOUT");err==nil{
  t.Fatal("network timeout must never quarantine a signed SSH proof")
 }
 if err=out.Ack(secondID);err!=nil{t.Fatal(err)}
 if _,err=out.Peek();!errors.Is(err,os.ErrNotExist){
  t.Fatal("root outbox still contains pending proof after acknowledgement")
 }
}
func TestOutboxQuarantineRejectsUnsafeDestinationAndOverwrite(t *testing.T){
 if os.Geteuid()!=0{t.Skip("root-only outbox test")}
 out:=&Outbox{Directory:filepath.Join(t.TempDir(),"proof-outbox")}
 if err:=os.Mkdir(out.Directory,0700);err!=nil{t.Fatal(err)}
 if err:=out.Quarantine("../../etc/passwd","CHALLENGE_NOT_ACTIVE");err==nil{
  t.Fatal("accepted path traversal in rejection ID")
 }
 if err:=out.Quarantine("10000000-0000-4000-8000-000000000001","UNKNOWN");err==nil{
  t.Fatal("accepted arbitrary archive reason")
 }
}
