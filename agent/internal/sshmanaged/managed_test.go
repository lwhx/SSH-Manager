package sshmanaged

import (
 "context"
 "os"
 "path/filepath"
 "strings"
 "testing"

 "github.com/lwhx/SSH-Manager/agent/internal/sshprobe"
)

const node="10000000-0000-4000-8000-000000000001"
func fixture(t *testing.T)(*Manager,*bool,*int){
 t.Helper()
 root:=t.TempDir()
 dir:=filepath.Join(root,"sshd_config.d")
 if err:=os.Mkdir(dir,0700);err!=nil{t.Fatal(err)}
 snap:=filepath.Join(root,"snap")
 if err:=os.Mkdir(snap,0700);err!=nil{t.Fatal(err)}
 main:=filepath.Join(root,"sshd_config")
 if err:=os.WriteFile(main,[]byte("Include "+dir+"/*.conf\nPasswordAuthentication yes\n"),0600);err!=nil{t.Fatal(err)}
 disabled:=new(bool);reloads:=new(int)
 m:=&Manager{MainPath:main,DropinPath:filepath.Join(dir,ManagedFileName),SnapshotDir:snap}
 m.Inspect=func(context.Context)(sshprobe.Effective,error){
  return sshprobe.Effective{PublicKeyAuthentication:true,
   PasswordAuthentication:!*disabled,KeyboardInteractive:!*disabled,
   Revision:map[bool]string{true:strings.Repeat("b",64),false:strings.Repeat("a",64)}[*disabled]},nil
 }
 m.Reload=func(context.Context)error{*reloads++;return nil}
 return m,disabled,reloads
}
func TestDisableAndManualRestore(t *testing.T){
 m,disabled,reloads:=fixture(t)
 before,_:=m.Inspect(context.Background())
 *disabled=true
 out,err:=m.Disable(context.Background(),node,"root",before)
 if err!=nil||out.AfterRevision==""||out.SnapshotRef==""||*reloads!=1{t.Fatalf("disable: %+v %v",out,err)}
 data,err:=os.ReadFile(m.DropinPath);if err!=nil||!strings.Contains(string(data),"PasswordAuthentication no"){t.Fatal("drop-in not present")}
 if _,err=m.Disable(context.Background(),node,"root",before);err==nil{t.Fatal("overwrote own drop-in")}
 *disabled=false
 restored,err:=m.Restore(context.Background(),node,"root",out.SnapshotRef,sshprobe.Effective{Revision:out.AfterRevision})
 if err!=nil||restored.AfterRevision!=before.Revision||*reloads!=2{t.Fatalf("manual restore: %+v %v",restored,err)}
 if _,err=os.Stat(m.DropinPath);!os.IsNotExist(err){t.Fatal("managed drop-in still active")}
}
func TestNeverAutomaticRollbackOnIneffectivePolicy(t *testing.T){
 m,_,reloads:=fixture(t)
 before,_:=m.Inspect(context.Background())
 out,err:=m.Disable(context.Background(),node,"root",before)
 if err==nil||out.SnapshotRef==""||*reloads!=0{t.Fatal("ineffective config must not reload or silently roll back")}
 if _,err=os.Stat(m.DropinPath);err!=nil{t.Fatal("manual repair evidence disappeared")}
}
func TestFailClosedOnAdminChangeAndOtherNode(t *testing.T){
 m,disabled,_:=fixture(t)
 before,_:=m.Inspect(context.Background())
 *disabled=true
 out,err:=m.Disable(context.Background(),node,"root",before);if err!=nil{t.Fatal(err)}
 *disabled=false
 if _,err=m.Restore(context.Background(),"20000000-0000-4000-8000-000000000001","root",out.SnapshotRef,before);err==nil{t.Fatal("wrong node accepted")}
 if err=os.WriteFile(m.DropinPath,[]byte("# changed by administrator\n"),0600);err!=nil{t.Fatal(err)}
 if _,err=m.Restore(context.Background(),node,"root",out.SnapshotRef,before);err==nil{t.Fatal("modified drop-in overwritten")}
 if _,err=os.Stat(m.DropinPath);err!=nil{t.Fatal("modified drop-in lost")}
}
func TestRejectUnsafeMainIncludeAndSymlink(t *testing.T){
 m,disabled,_:=fixture(t)
 before,_:=m.Inspect(context.Background());*disabled=true
 if err:=os.WriteFile(m.MainPath,[]byte("PasswordAuthentication yes\nInclude "+filepath.Dir(m.DropinPath)+"/*.conf\n"),0600);err!=nil{t.Fatal(err)}
 if _,err:=m.Disable(context.Background(),node,"root",before);err==nil{t.Fatal("non-first Include accepted")}
 if err:=os.Remove(m.MainPath);err!=nil{t.Fatal(err)}
 if err:=os.Symlink(filepath.Join(filepath.Dir(m.MainPath),"other"),m.MainPath);err!=nil{t.Fatal(err)}
 if _,err:=m.Disable(context.Background(),node,"root",before);err==nil{t.Fatal("symlink main accepted")}
}
