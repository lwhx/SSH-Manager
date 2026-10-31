package sshkeys

import (
 "bytes"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/base64"
 "encoding/binary"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func key(t *testing.T)string{
 t.Helper()
 pub,_,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 b:=make([]byte,51)
 binary.BigEndian.PutUint32(b[0:4],11);copy(b[4:15],[]byte("ssh-ed25519"))
 binary.BigEndian.PutUint32(b[15:19],32);copy(b[19:51],pub)
 return "ssh-ed25519 "+base64.StdEncoding.EncodeToString(b)+" example"
}

func TestInstallPreservesOriginalAndIsIdempotent(t *testing.T){
 home:=filepath.Join(t.TempDir(),"user")
 if err:=os.Mkdir(home,0700);err!=nil{t.Fatal(err)}
 ssh:=filepath.Join(home,".ssh")
 if err:=os.Mkdir(ssh,0700);err!=nil{t.Fatal(err)}
 existing:=[]byte("# existing user key\nssh-rsa AAAATEST original\n")
 path:=filepath.Join(ssh,"authorized_keys")
 if err:=os.WriteFile(path,existing,0600);err!=nil{t.Fatal(err)}
 snapshot:=filepath.Join(t.TempDir(),"snapshots")
 pub:=key(t)
 result,err:=InstallDaily(home,os.Getuid(),os.Getgid(),pub,snapshot)
 if err!=nil{t.Fatal(err)}
 if !result.FileChecked||result.AlreadyPresent||result.SnapshotRef==""{t.Fatalf("incorrect result: %+v",result)}
 data,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
 if !bytes.HasPrefix(data,existing){t.Fatal("changed preexisting authorized_keys")}
 if !strings.Contains(string(data),"ssh-manager-daily"){t.Fatal("new key missing")}
 saved,err:=os.ReadFile(filepath.Join(snapshot,result.SnapshotRef+".authorized_keys"))
 if err!=nil||!bytes.Equal(saved,existing){t.Fatal("snapshot did not capture old bytes")}
 second,err:=InstallDaily(home,os.Getuid(),os.Getgid(),pub,snapshot)
 if err!=nil||!second.AlreadyPresent{t.Fatalf("duplicate install failed: %v %+v",err,second)}
 data2,_:=os.ReadFile(path)
 if !bytes.Equal(data,data2){t.Fatal("duplicate changed file")}
}

func TestRejectsSymlinkAndWeakPermissions(t *testing.T){
 home:=filepath.Join(t.TempDir(),"user");_ = os.Mkdir(home,0700)
 ssh:=filepath.Join(home,".ssh");_ = os.Mkdir(ssh,0700)
 external:=filepath.Join(t.TempDir(),"other")
 _ = os.WriteFile(external,[]byte("do not touch"),0600)
 _ = os.Symlink(external,filepath.Join(ssh,"authorized_keys"))
 if _,err:=InstallDaily(home,os.Getuid(),os.Getgid(),key(t),filepath.Join(t.TempDir(),"snaps"));err==nil{t.Fatal("authorized_keys symlink accepted")}
 _ = os.Remove(filepath.Join(ssh,"authorized_keys"))
 _ = os.WriteFile(filepath.Join(ssh,"authorized_keys"),[]byte("safe"),0666)
 _ = os.Chmod(filepath.Join(ssh,"authorized_keys"),0666)
 if _,err:=InstallDaily(home,os.Getuid(),os.Getgid(),key(t),filepath.Join(t.TempDir(),"snaps"));err==nil{t.Fatal("group writable authorized_keys accepted")}
}
func TestPublicKeyValidation(t *testing.T){
 k:=key(t)
 if _,_,err:=NormalizeED25519(k);err!=nil{t.Fatal(err)}
 for _,bad:=range []string{"ssh-rsa AAAA",k+"\nssh-ed25519 MALICIOUS","ssh-ed25519 abc","command=evil "+k}{
  if _,_,err:=NormalizeED25519(bad);err==nil{t.Fatalf("bad key accepted %q",bad)}
 }
}

func TestRejectsSymlinkInHomeAncestry(t *testing.T){
 base:=t.TempDir()
 realHome:=filepath.Join(base,"actual","user")
 if err:=os.MkdirAll(realHome,0700);err!=nil{t.Fatal(err)}
 homeLink:=filepath.Join(base,"alias")
 if err:=os.Symlink(filepath.Join(base,"actual"),homeLink);err!=nil{t.Fatal(err)}
 aliasHome:=filepath.Join(homeLink,"user")
 _,err:=InstallDaily(aliasHome,os.Getuid(),os.Getgid(),key(t),filepath.Join(t.TempDir(),"snapshots"))
 if err==nil{t.Fatal("symlink ancestor accepted")}
 if _,err:=os.Stat(filepath.Join(realHome,".ssh","authorized_keys"));!os.IsNotExist(err){
  t.Fatal("symlink ancestor redirected privileged write")
 }
}
