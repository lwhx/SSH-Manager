package sshproof
import(
 "crypto/ed25519"
 "crypto/rand"
 "strings"
 "testing"
)
func TestEd25519RootAttestationVerifiesOnlyExactSignedBytes(t *testing.T){
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 data:=Attestation{Version:1,ProofID:"20000000-0000-4000-8000-000000000001",
 NodeID:"10000000-0000-4000-8000-000000000001",VerificationID:"30000000-0000-4000-8000-000000000001",
 KeyID:"40000000-0000-4000-8000-000000000001",LoginUser:"root",Fingerprint:fingerprint,ConfigRevision:strings.Repeat("a",64),
 NonceHash:strings.Repeat("b",64),AuthenticatedAt:1793440003,ObservedAt:1793440005,ClientIP:"127.0.0.1",ClientPort:52334,SSHDPID:12}
 signed,err:=SignAttestation(data,priv);if err!=nil{t.Fatal(err)}
 decoded,err:=VerifyAttestation(signed,pub);if err!=nil||decoded!=data{t.Fatalf("proof round-trip failed: %v",err)}
 signed.Payload+=" "
 if _,err:=VerifyAttestation(signed,pub);err==nil{t.Fatal("tampered proof accepted")}
 _,other,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 another,_:=SignAttestation(data,other)
 if _,err:=VerifyAttestation(another,pub);err==nil{t.Fatal("proof from unpinned key accepted")}
}
