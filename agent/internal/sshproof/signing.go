package sshproof

import (
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "encoding/base64"
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "syscall"
)

// Attestation is a root-only assertion about a new, SSHD-authenticated
// session. The nonce itself is never exposed to the Agent/control service.
// Canonical Go JSON bytes are signed without rewriting them in transit.
type Attestation struct {
 Version int `json:"v"`
 ProofID string `json:"proof_id"`
 NodeID string `json:"node_id"`
 VerificationID string `json:"verification_id"`
 KeyID string `json:"key_id"`
 LoginUser string `json:"login_user"`
 Fingerprint string `json:"fingerprint"`
 ConfigRevision string `json:"config_revision"`
 NonceHash string `json:"nonce_hash"`
 AuthenticatedAt int64 `json:"authenticated_at"`
 ObservedAt int64 `json:"observed_at"`
 ClientIP string `json:"client_ip"`
 ClientPort uint16 `json:"client_port"`
 SSHDPID int `json:"sshd_pid"`
}
type SignedAttestation struct{
 Payload string `json:"payload"`
 Signature string `json:"signature"`
}
func SignAttestation(p Attestation,private ed25519.PrivateKey)(SignedAttestation,error){
 var signed SignedAttestation
 if len(private)!=ed25519.PrivateKeySize{return signed,errors.New("invalid proof signing key")}
 raw,err:=json.Marshal(p);if err!=nil{return signed,err}
 if len(raw)>4096{return signed,errors.New("proof exceeds signed envelope limit")}
 signed.Payload=string(raw)
 signed.Signature=base64.RawURLEncoding.EncodeToString(ed25519.Sign(private,raw))
 return signed,nil
}
func VerifyAttestation(s SignedAttestation,pub ed25519.PublicKey)(Attestation,error){
 var p Attestation
 if len(pub)!=ed25519.PublicKeySize||len(s.Payload)>4096||len(s.Signature)>120{
  return p,errors.New("invalid proof envelope")
 }
 sig,err:=base64.RawURLEncoding.DecodeString(s.Signature)
 if err!=nil||!ed25519.Verify(pub,[]byte(s.Payload),sig){
  return p,errors.New("root proof signature invalid")
 }
 if err=json.Unmarshal([]byte(s.Payload),&p);err!=nil{return p,err}
 return p,nil
}
func ProofPublicKey(private ed25519.PrivateKey)string{
 return base64.RawURLEncoding.EncodeToString(private.Public().(ed25519.PublicKey))
}
func ProofPublicFingerprint(public ed25519.PublicKey)string{
 digest:=sha256.Sum256(public)
 return fmt.Sprintf("SHA256:%s",base64.RawStdEncoding.EncodeToString(digest[:]))
}
func checkedPrivateFile(path string)(*os.File,error){
 fd,err:=syscall.Open(path,syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0)
 if err!=nil{return nil,err}
 f:=os.NewFile(uintptr(fd),path)
 st,err:=f.Stat()
 if err!=nil||!st.Mode().IsRegular()||st.Mode().Perm()!=0600{
  _=f.Close();return nil,errors.New("root proof key must be private regular file mode 0600")
 }
 owner,ok:=st.Sys().(*syscall.Stat_t)
 if !ok||owner.Uid!=0{_ = f.Close();return nil,errors.New("root proof key is not root-owned")}
 return f,nil
}
func CheckKeyDirectory(dir string)error{
 if !filepath.IsAbs(dir)||filepath.Clean(dir)!=dir||dir=="/"{
  return errors.New("unsafe root proof key directory")
 }
 st,err:=os.Lstat(dir)
 if err!=nil||!st.IsDir()||st.Mode().Perm()&0077!=0{
  return errors.New("unsafe root proof key directory permissions")
 }
 owner,ok:=st.Sys().(*syscall.Stat_t)
 if !ok||owner.Uid!=0{return errors.New("root proof key directory owner mismatch")}
 return nil
}
// GenerateRootProofKey must be called EXPLICITLY by root on the test VPS.
func GenerateRootProofKey(path string)(string,error){
 if os.Geteuid()!=0{return "",errors.New("root required for proof key generation")}
 if err:=CheckKeyDirectory(filepath.Dir(path));err!=nil{return "",err}
 pub,private,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{return "",err}
 f,err:=os.OpenFile(path,os.O_WRONLY|os.O_EXCL|os.O_CREATE,0600)
 if err!=nil{return "",err}
 raw:=base64.RawURLEncoding.EncodeToString(private)
 if _,err=f.WriteString(raw);err!=nil{_ = f.Close();return "",err}
 if err=f.Sync();err!=nil{_ = f.Close();return "",err}
 if err=f.Close();err!=nil{return "",err}
 dir,err:=os.Open(filepath.Dir(path));if err!=nil{return "",err}
 defer dir.Close()
 if err=dir.Sync();err!=nil{return "",err}
 return base64.RawURLEncoding.EncodeToString(pub),nil
}
func LoadRootProofKey(path string)(ed25519.PrivateKey,error){
 if os.Geteuid()!=0{return nil,errors.New("root proof signing key requires root")}
 if err:=CheckKeyDirectory(filepath.Dir(path));err!=nil{return nil,err}
 f,err:=checkedPrivateFile(path);if err!=nil{return nil,err}
 defer f.Close()
 data:=make([]byte,129)
 n,err:=f.Read(data)
 if err!=nil&&n==0{return nil,err}
 if n>128{return nil,errors.New("invalid proof key size")}
 decoded,err:=base64.RawURLEncoding.DecodeString(string(data[:n]))
 if err!=nil||len(decoded)!=ed25519.PrivateKeySize{return nil,errors.New("invalid root proof signing key")}
 return ed25519.PrivateKey(decoded),nil
}
