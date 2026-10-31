//go:build ssh_integration && linux

package sshkeys

import (
 "bytes"
 "crypto/rand"
 "encoding/hex"
 "fmt"
 "net"
 "os"
 "os/exec"
 "os/user"
 "path/filepath"
 "strconv"
 "strings"
 "testing"
 "time"
)

// TestLocalSSHDIntegration uses only ephemeral loopback OpenSSH resources on
// an isolated CI runner. It never touches production sshd_config or real VPSs.
func TestLocalSSHDIntegration(t *testing.T){
 if os.Geteuid()!=0{t.Fatal("SSH integration must run as root on an isolated CI runner")}
 if _,err:=os.Stat("/usr/sbin/sshd");err!=nil{t.Fatal("openssh-server required: ",err)}
 root:=t.TempDir()
 if err:=os.Chmod(root,0755);err!=nil{t.Fatal(err)}
 random:=make([]byte,5)
 if _,err:=rand.Read(random);err!=nil{t.Fatal(err)}
 username:="smci"+hex.EncodeToString(random)
 home:=filepath.Join(root,"home")
 if err:=os.Mkdir(home,0700);err!=nil{t.Fatal(err)}
 if out,err:=exec.Command("useradd","--no-create-home","--home-dir",home,"--shell","/bin/sh",username).CombinedOutput();err!=nil{
  t.Fatalf("create isolated CI user: %v %s",err,out)
 }
 t.Cleanup(func(){_ = exec.Command("userdel",username).Run()})
 account,err:=user.Lookup(username)
 if err!=nil{t.Fatal(err)}
 uid,err:=strconv.Atoi(account.Uid);if err!=nil{t.Fatal(err)}
 gid,err:=strconv.Atoi(account.Gid);if err!=nil{t.Fatal(err)}
 if err:=os.Chown(home,uid,gid);err!=nil{t.Fatal(err)}
 // A locked test account may be rejected by OpenSSH even for pubkey auth.
 password:=make([]byte,24)
 if _,err:=rand.Read(password);err!=nil{t.Fatal(err)}
 cmd:=exec.Command("chpasswd")
 cmd.Stdin=strings.NewReader(username+":"+hex.EncodeToString(password)+"\n")
 if out,err:=cmd.CombinedOutput();err!=nil{t.Fatalf("enable isolated CI account: %v %s",err,out)}

 hostKey:=filepath.Join(root,"host_ed25519")
 clientKey:=filepath.Join(root,"client_ed25519")
 wrongKey:=filepath.Join(root,"wrong_ed25519")
 for _,path:=range []string{hostKey,clientKey,wrongKey}{
  if out,err:=exec.Command("ssh-keygen","-q","-t","ed25519","-N","","-f",path).CombinedOutput();err!=nil{
   t.Fatalf("key generation: %v %s",err,out)
  }
 }
 pub,err:=os.ReadFile(clientKey+".pub");if err!=nil{t.Fatal(err)}
 listener,err:=net.Listen("tcp","127.0.0.1:0")
 if err!=nil{t.Fatal(err)}
 port:=listener.Addr().(*net.TCPAddr).Port
 _=listener.Close()
 if err:=os.MkdirAll("/run/sshd",0755);err!=nil{t.Fatal(err)}
 conf:=filepath.Join(root,"sshd_test.conf")
 text:=fmt.Sprintf(
  "Port %d\nListenAddress 127.0.0.1\nHostKey %s\nPidFile %s\n"+
  "AuthorizedKeysFile .ssh/authorized_keys\nPubkeyAuthentication yes\n"+
  "PasswordAuthentication yes\nKbdInteractiveAuthentication no\n"+
  "UsePAM no\nPermitRootLogin no\nStrictModes yes\n"+
  "AllowUsers %s\nLogLevel VERBOSE\n",
  port,hostKey,filepath.Join(root,"sshd.pid"),username,
 )
 if err:=os.WriteFile(conf,[]byte(text),0600);err!=nil{t.Fatal(err)}
 if out,err:=exec.Command("/usr/sbin/sshd","-t","-f",conf).CombinedOutput();err!=nil{
  t.Fatalf("isolated sshd config invalid: %v %s",err,out)
 }
 server:=exec.Command("/usr/sbin/sshd","-D","-e","-f",conf)
 var serverLog bytes.Buffer
 server.Stderr=&serverLog
 if err:=server.Start();err!=nil{t.Fatal(err)}
 t.Cleanup(func(){if server.Process!=nil{_ = server.Process.Kill();_ = server.Wait()}})
 // Wait for local test listener instead of relying on startup timing.
 ready:=false
 for i:=0;i<60;i++{
  c,err:=net.DialTimeout("tcp",fmt.Sprintf("127.0.0.1:%d",port),200*time.Millisecond)
  if err==nil{_ = c.Close();ready=true;break}
  time.Sleep(100*time.Millisecond)
 }
 if !ready{t.Fatalf("isolated sshd did not start: %s",serverLog.String())}
 sshAttempt:=func(keyfile string)(string,error){
  args:=[]string{"-T","-p",strconv.Itoa(port),
   "-o","BatchMode=yes","-o","IdentitiesOnly=yes","-o","IdentityAgent=none",
   "-o","PreferredAuthentications=publickey","-o","PasswordAuthentication=no",
   "-o","KbdInteractiveAuthentication=no","-o","NumberOfPasswordPrompts=0",
   "-o","ControlMaster=no","-o","ControlPath=none","-o","ConnectTimeout=2",
   "-o","StrictHostKeyChecking=no","-o","UserKnownHostsFile=/dev/null",
   "-i",keyfile,username+"@127.0.0.1","printf ssh-login-ok"}
  b,e:=exec.Command("ssh",args...).CombinedOutput()
  return string(b),e
 }
 if _,err:=sshAttempt(clientKey);err==nil{t.Fatal("SSH accepted daily key before installation")}
 result,err:=InstallDaily(home,uid,gid,string(pub),filepath.Join(root,"snapshots"))
 if err!=nil{t.Fatalf("authorized_keys install: %v",err)}
 if !result.FileChecked||result.SnapshotRef==""{t.Fatalf("invalid installation report %+v",result)}
 output,err:=sshAttempt(clientKey)
 if err!=nil{t.Fatalf("new SSH public-key login failed: %v %s | sshd: %s",err,output,serverLog.String())}
 if !strings.Contains(output,"ssh-login-ok"){t.Fatalf("SSH command was not executed: %s",output)}
 if _,err:=sshAttempt(wrongKey);err==nil{t.Fatal("wrong private key unexpectedly authenticated")}
 effective,err:=exec.Command("/usr/sbin/sshd","-T","-f",conf,"-C",
  fmt.Sprintf("user=%s,host=127.0.0.1,addr=127.0.0.1,laddr=127.0.0.1,lport=%d",username,port)).Output()
 if err!=nil{t.Fatal(err)}
 if !strings.Contains(string(effective),"passwordauthentication yes\n"){
  t.Fatal("daily key installation must never disable password login")
 }
 // Also ensure no mutations to this isolated sshd configuration.
 unchanged,err:=os.ReadFile(conf)
 if err!=nil||string(unchanged)!=text{t.Fatal("sshd_config changed unexpectedly")}
}
