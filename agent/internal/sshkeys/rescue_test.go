package sshkeys

import (
 "crypto/ed25519"
 "crypto/rand"
 "encoding/base64"
 "encoding/binary"
 "os"
 "path/filepath"
 "strings"
 "testing"
)
func rescueFixture(t *testing.T)string{
 t.Helper()
 pub,_,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{t.Fatal(err)}
 b:=make([]byte,51);binary.BigEndian.PutUint32(b[:4],11)
 copy(b[4:15],[]byte("ssh-ed25519"))
 binary.BigEndian.PutUint32(b[15:19],32)
 copy(b[19:],pub)
 return "ssh-ed25519 "+base64.StdEncoding.EncodeToString(b)
}
func TestRescueKeyEnableAndExactRevoke(t *testing.T){
 user:=os.Geteuid();group:=os.Getegid()
 home:=t.TempDir()
 snap:=filepath.Join(t.TempDir(),"snapshots")
 other:=rescueFixture(t)
 key:=rescueFixture(t)
 sshDir:=filepath.Join(home,".ssh")
 if err:=os.Mkdir(sshDir,0700);err!=nil{t.Fatal(err)}
 existing:=other+" operator-own-key\n"
 if err:=os.WriteFile(filepath.Join(sshDir,"authorized_keys"),[]byte(existing),0600);err!=nil{t.Fatal(err)}
 a,err:=InstallRescue(home,user,group,key,snap)
 if err!=nil||!a.FileChecked{t.Fatalf("enable rescue: %+v %v",a,err)}
 before,err:=os.ReadFile(filepath.Join(sshDir,"authorized_keys"))
 if err!=nil||!strings.Contains(string(before),"ssh-manager-rescue"){t.Fatal("rescue key absent")}
 got,err:=RevokeRescue(home,user,group,key,snap)
 if err!=nil||!got.FileChecked||got.SnapshotRef==""{t.Fatalf("revoke rescue: %+v %v",got,err)}
 after,err:=os.ReadFile(filepath.Join(sshDir,"authorized_keys"))
 if err!=nil||string(after)!=existing{t.Fatalf("unrelated authorized_keys modified: %s %v",string(after),err)}
 if _,err=RevokeRescue(home,user,group,key,snap);err==nil{t.Fatal("second revoke should fail")}
}
func TestRescueRevokeRefusesUnmanagedKey(t *testing.T){
 user:=os.Geteuid();group:=os.Getegid()
 home:=t.TempDir();sshDir:=filepath.Join(home,".ssh")
 if err:=os.Mkdir(sshDir,0700);err!=nil{t.Fatal(err)}
 key:=rescueFixture(t)
 original:=key+" handwritten-admin-key\n"
 if err:=os.WriteFile(filepath.Join(sshDir,"authorized_keys"),[]byte(original),0600);err!=nil{t.Fatal(err)}
 if _,err:=RevokeRescue(home,user,group,key,filepath.Join(t.TempDir(),"snaps"));err==nil{t.Fatal("unmanaged key revoked")}
 current,_:=os.ReadFile(filepath.Join(sshDir,"authorized_keys"))
 if string(current)!=original{t.Fatal("unmanaged key modified")}
}
