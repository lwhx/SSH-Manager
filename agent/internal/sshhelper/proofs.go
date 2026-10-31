package sshhelper

import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/base64"
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "strconv"
 "strings"
 "syscall"
 "time"

 "github.com/lwhx/SSH-Manager/agent/internal/sshproof"
)

type ProofRequest struct {
 VerificationID string `json:"verification_id"`
 Nonce string `json:"nonce"`
}
type ProofResult struct {
 OK bool `json:"ok"`
 Code string `json:"code"`
}
type Outbox struct{Directory string}
func(o *Outbox)validate()error{
 if o==nil||!filepath.IsAbs(o.Directory)||filepath.Clean(o.Directory)!=o.Directory{
  return errors.New("unsafe root proof outbox path")
 }
 st,err:=os.Lstat(o.Directory)
 if err!=nil||!st.IsDir()||st.Mode().Perm()&0077!=0{return errors.New("root proof outbox unavailable")}
 owner,ok:=st.Sys().(*syscall.Stat_t)
 if !ok||owner.Uid!=0{return errors.New("root proof outbox owner mismatch")}
 return nil
}
func(o *Outbox)Save(id string,s sshproof.SignedAttestation)error{
 if !uuidRE.MatchString(id){return errors.New("invalid attestation ID")}
 if err:=o.validate();err!=nil{return err}
 raw,err:=json.Marshal(s);if err!=nil{return err}
 if len(raw)>8192{return errors.New("attestation oversized")}
 f,err:=os.OpenFile(filepath.Join(o.Directory,id+".json"),os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
 if err!=nil{return err}
 if _,err=f.Write(raw);err!=nil{_ = f.Close();return err}
 if err=f.Sync();err!=nil{_ = f.Close();return err}
 if err=f.Close();err!=nil{return err}
 d,err:=os.Open(o.Directory);if err!=nil{return err}
 defer d.Close();return d.Sync()
}
func(o *Outbox)Peek()(sshproof.SignedAttestation,error){
 var result sshproof.SignedAttestation
 if err:=o.validate();err!=nil{return result,err}
 entries,err:=os.ReadDir(o.Directory);if err!=nil{return result,err}
 for _,entry:=range entries{
  name:=entry.Name()
  if entry.IsDir()||!strings.HasSuffix(name,".json"){continue}
  id:=strings.TrimSuffix(name,".json")
  if !uuidRE.MatchString(id){continue}
  path:=filepath.Join(o.Directory,name)
  fd,err:=syscall.Open(path,syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0)
  if err!=nil{return result,err}
  f:=os.NewFile(uintptr(fd),name)
  st,err:=f.Stat()
  if err!=nil||!st.Mode().IsRegular()||st.Size()>8192||st.Mode().Perm()&0077!=0{
   _ = f.Close();return result,errors.New("unsafe outbox proof file")
  }
  var s sshproof.SignedAttestation
  dec:=json.NewDecoder(f);err=dec.Decode(&s);_ = f.Close()
  if err!=nil||s.Payload==""||s.Signature==""{return result,errors.New("invalid outbox entry")}
  var att sshproof.Attestation
  if json.Unmarshal([]byte(s.Payload),&att)!=nil||att.ProofID!=id{
   return result,errors.New("signed proof identity mismatch")
  }
  return s,nil
 }
 return result,os.ErrNotExist
}
// Quarantine preserves permanently rejected proofs under a private root-only
// directory, rather than deleting them or blocking newer challenges. Only
// explicit terminal gateway error codes are permitted as reasons.
func(o *Outbox)Quarantine(proofID,reason string)error{
 if !uuidRE.MatchString(proofID){return errors.New("invalid rejected proof ID")}
 switch reason{
 case "CHALLENGE_NOT_ACTIVE","CHALLENGE_CONTEXT_CHANGED","PROOF_ALREADY_USED_OR_CONTEXT_CHANGED":
 default:return errors.New("untrusted proof quarantine reason")
 }
 if err:=o.validate();err!=nil{return err}
 src:=filepath.Join(o.Directory,proofID+".json")
 st,err:=os.Lstat(src)
 if err!=nil{return err}
 owner,ok:=st.Sys().(*syscall.Stat_t)
 if !ok||owner.Uid!=0||!st.Mode().IsRegular()||st.Mode().Perm()&0077!=0{
  return errors.New("unsafe rejected proof source")
 }
 dead:=filepath.Join(o.Directory,"rejected")
 if err=os.Mkdir(dead,0700);err!=nil&&!errors.Is(err,os.ErrExist){return err}
 meta,err:=os.Lstat(dead)
 if err!=nil{return err}
 deadOwner,ok:=meta.Sys().(*syscall.Stat_t)
 if !ok||!meta.IsDir()||meta.Mode().Perm()&0077!=0||deadOwner.Uid!=0{
  return errors.New("unsafe root-only rejected proof directory")
 }
 dest:=filepath.Join(dead,proofID+".json")
 if _,err=os.Lstat(dest);err==nil{
  return errors.New("rejected proof ID already archived")
 }else if !errors.Is(err,os.ErrNotExist){return err}
 if err=os.Rename(src,dest);err!=nil{return err}
 f,err:=os.OpenFile(filepath.Join(dead,proofID+".reason"),os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
 if err!=nil{return err}
 if _,err=f.WriteString(reason+"\n");err!=nil{_ = f.Close();return err}
 if err=f.Sync();err!=nil{_ = f.Close();return err}
 if err=f.Close();err!=nil{return err}
 for _,name:=range []string{dead,o.Directory}{
  directory,err:=os.Open(name)
  if err!=nil{return err}
  err=directory.Sync()
  _=directory.Close()
  if err!=nil{return err}
 }
 return nil
}

func(o *Outbox)Ack(proofID string)error{
 if !uuidRE.MatchString(proofID){return errors.New("invalid proof id")}
 if err:=o.validate();err!=nil{return err}
 if err:=os.Remove(filepath.Join(o.Directory,proofID+".json"));err!=nil{return err}
 d,err:=os.Open(o.Directory);if err!=nil{return err}
 defer d.Close();return d.Sync()
}

func(h *Handler)ProveSession(ctx context.Context,peerPID,peerUID int,request ProofRequest)ProofResult{
 h.defaults()
 fail:=func(code string)ProofResult{return ProofResult{Code:code}}
 if err:=h.Config.Validate();err!=nil{return fail("INVALID_ROOT_HELPER_CONFIGURATION")}
 if h.EUID()!=0||!h.Config.EnableSSHProof||h.Challenges==nil||
  h.Outbox==nil||len(h.ProofSigningKey)!=ed25519.PrivateKeySize{
  return fail("PROOF_FEATURE_DISABLED")
 }
 if !uuidRE.MatchString(request.VerificationID)||len(request.Nonce)!=43{
  return fail("INVALID_PROOF_REQUEST")
 }
 prepared,err:=h.Challenges.Read(request.VerificationID)
 if err!=nil{return fail("CHALLENGE_NOT_PREPARED")}
 now:=h.Clock()
 if err=prepared.Validate(h.Config.AllowedUser,prepared.ConfigRevision,now);err!=nil{
  return fail("CHALLENGE_STALE")
 }
 if prepared.PreparedAt<=0||prepared.PreparedAt>=prepared.ExpiresAt{
  return fail("INVALID_PREPARATION_TIME")
 }
 account,err:=h.Lookup(h.Config.AllowedUser)
 if err!=nil{return fail("SSH_USER_NOT_FOUND")}
 uid,err:=strconv.Atoi(account.Uid)
 if err!=nil||uid!=peerUID{return fail("SSH_PROOF_UID_MISMATCH")}
 policy,err:=h.Inspect(ctx,h.Config)
 if err!=nil||policy.Revision!=prepared.ConfigRevision||
  policy.DailyKeyEligibility(h.Config.AllowedUser)!=nil{
  return fail("SSH_POLICY_CHANGED")
 }
 from:=prepared.PreparedAt
 if prepared.IssuedAt>from{from=prepared.IssuedAt}
 challenge:=sshproof.Challenge{LoginUser:prepared.LoginUser,
  KeyFingerprint:prepared.Fingerprint,IssuedAt:time.Unix(from,0),
  ExpiresAt:time.Unix(prepared.ExpiresAt,0)}
 if !challenge.IssuedAt.Before(challenge.ExpiresAt){return fail("PROOF_WINDOW_CLOSED")}
 event,err:=h.ObserveSSH(ctx,peerPID,challenge,h.ProcessReader)
 if err!=nil{return fail("TRUSTED_SSH_LOGIN_NOT_OBSERVED")}
 challenge.ClientIP=event.ClientIP;challenge.ClientPort=event.ClientPort
 if err=sshproof.VerifyLocalSSHProof(sshproof.TrustedPeer{PID:peerPID,RealUID:peerUID},
  uid,request.Nonce,prepared.NonceHash,challenge,event,h.ProcessReader);err!=nil{
  return fail("SSH_PROOF_REJECTED")
 }
 random:=make([]byte,16)
 if _,err=rand.Read(random);err!=nil{return fail("PROOF_ENTROPY_FAILED")}
 random[6]=(random[6]&0x0f)|0x40;random[8]=(random[8]&0x3f)|0x80
 proofID:=fmt.Sprintf("%x-%x-%x-%x-%x",random[:4],random[4:6],random[6:8],random[8:10],random[10:])
 att:=sshproof.Attestation{
  Version:1,ProofID:proofID,NodeID:h.Config.NodeID,
  VerificationID:prepared.VerificationID,KeyID:prepared.KeyID,
  LoginUser:prepared.LoginUser,Fingerprint:prepared.Fingerprint,
  ConfigRevision:prepared.ConfigRevision,NonceHash:prepared.NonceHash,
  AuthenticatedAt:event.Timestamp.Unix(),ObservedAt:now.Unix(),
  ClientIP:event.ClientIP,ClientPort:event.ClientPort,SSHDPID:event.PID,
 }
 if err=h.Challenges.ClaimVerifiedProof(prepared.VerificationID);err!=nil{
  return fail("PROOF_ALREADY_ISSUED_ON_THIS_VPS")
 }
 signed,err:=sshproof.SignAttestation(att,h.ProofSigningKey)
 if err!=nil{return fail("SIGNING_FAILED")}
 if err=h.Outbox.Save(att.ProofID,signed);err!=nil{return fail("PROOF_OUTBOX_UNAVAILABLE")}
 return ProofResult{OK:true,Code:"SIGNED_PROOF_QUEUED"}
}
func RootProofPublicKey(priv ed25519.PrivateKey)string{
 return base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
}
