package sshhelper

import (
 "os"
 "path/filepath"
 "testing"
 "time"
)
func preparedFixture()PreparedChallenge{
 return PreparedChallenge{
  VerificationID:"40000000-0000-4000-8000-000000000001",
  KeyID:"50000000-0000-4000-8000-000000000001",
  NonceHash:"b9c0472f93fd786d5d9d33f355e00d439ad6dbde358e649d85c12fa14e3e101a",
  Fingerprint:"SHA256:WqyC1TNJwaA73QFZwyV9a7G2SpMUEMDwVZ7OEWHsMmg",
  LoginUser:"root",ConfigRevision:"a3d27e224b539bb25314657d8e99eaa14288cd068b255c3474afdf967bb44991",
  IssuedAt:1000,ExpiresAt:1300,
 }
}
func TestPreparedChallengeRequiresExactUserKeyRevisionAndTime(t *testing.T){
 p:=preparedFixture()
 if err:=p.Validate("root",p.ConfigRevision,time.Unix(1050,0));err!=nil{t.Fatal(err)}
 bad:=[]struct{name string;change func(*PreparedChallenge)}{
  {"wrong user",func(p *PreparedChallenge){p.LoginUser="ubuntu"}},
  {"wrong fingerprint",func(p *PreparedChallenge){p.Fingerprint="bogus"}},
  {"wrong hash",func(p *PreparedChallenge){p.NonceHash="abc"}},
  {"expired",func(p *PreparedChallenge){p.ExpiresAt=1001}},
  {"too long",func(p *PreparedChallenge){p.ExpiresAt=1400}},
  {"bad revision",func(p *PreparedChallenge){p.ConfigRevision="unverified"}},
 }
 for _,tc:=range bad{t.Run(tc.name,func(t *testing.T){
  changed:=p;tc.change(&changed)
  if err:=changed.Validate("root",p.ConfigRevision,time.Unix(1050,0));err==nil{t.Fatal("accepted invalid preparation")}
 })}
}
func TestChallengeStoreIsRootOnlyAndNoOverwrite(t *testing.T){
 dir:=filepath.Join(t.TempDir(),"challenges")
 store:=&ChallengeStore{Directory:dir};p:=preparedFixture()
 if err:=store.Save(p);err!=nil{t.Fatal(err)}
 if err:=store.Save(p);err==nil{t.Fatal("replay overwrote challenge")}
 got,err:=store.Read(p.VerificationID)
 if err!=nil||got.HashSummary()!=p.HashSummary(){t.Fatalf("challenge recovery failed: %v",err)}
 if err:=os.Chmod(dir,0777);err!=nil{t.Fatal(err)}
 if err:=store.Save(PreparedChallenge{VerificationID:"40000000-0000-4000-8000-000000000002"});err==nil{
  t.Fatal("unsafe challenge directory accepted")
 }
}
