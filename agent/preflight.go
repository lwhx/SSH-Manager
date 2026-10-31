package main

import (
 "bufio"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
)
// Read-only inventory. NEVER treat this as permission to change sshd config;
// authenticated SSH proof and root-owned effective-config inspection come later.
func readOnlyPreflight()map[string]any{
 r:=map[string]any{
  "mode":"READ_ONLY","ssh_writes_allowed":false,
  "trusted_ssh_verification":false,"effective_config_checked":false,
 }
 if hostname,err:=os.Hostname();err==nil{r["hostname"]=hostname}
 if f,err:=os.Open("/etc/os-release");err==nil{
  defer f.Close()
  s:=bufio.NewScanner(f)
  for s.Scan(){
   line:=s.Text()
   if strings.HasPrefix(line,"ID="){
    r["os_id"]=strings.Trim(strings.TrimPrefix(line,"ID="),"\"'")
    break
   }
  }
 }
 paths:=[]string{"/usr/sbin/sshd","/usr/local/sbin/sshd","/sbin/sshd"}
 if x,err:=exec.LookPath("sshd");err==nil{paths=append([]string{x},paths...)}
 for _,p:=range paths{
  if info,err:=os.Stat(p);err==nil&&info.Mode().IsRegular()&&info.Mode()&0111!=0{
   r["sshd_present"]=true;r["sshd_path"]=filepath.Clean(p);return r
  }
 }
 r["sshd_present"]=false
 return r
}
