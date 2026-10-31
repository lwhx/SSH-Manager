//go:build linux

package sshproof

import (
 "errors"
 "fmt"
 "os"
 "strconv"
 "strings"
)

// ProcState must come from root-readable /proc, never a caller-supplied
// SSH_CONNECTION string or a process environment variable.
type ProcState struct {
 PID int
 PPID int
 RealUID int
 Executable string
}
type ProcessReader func(pid int)(ProcState,error)
func ReadLinuxProcess(pid int)(ProcState,error){
 var p ProcState
 if pid<=1{return p,errors.New("invalid Linux process id")}
 status,err:=os.ReadFile(fmt.Sprintf("/proc/%d/status",pid))
 if err!=nil||len(status)>32768{return p,errors.New("cannot safely inspect process")}
 p.PID=pid;p.PPID=-1;p.RealUID=-1
 for _,line:=range strings.Split(string(status),"\n"){
  if strings.HasPrefix(line,"PPid:"){
   fields:=strings.Fields(strings.TrimPrefix(line,"PPid:"))
   if len(fields)==1{p.PPID,_=strconv.Atoi(fields[0])}
  }
  if strings.HasPrefix(line,"Uid:"){
   fields:=strings.Fields(strings.TrimPrefix(line,"Uid:"))
   if len(fields)==4{p.RealUID,_=strconv.Atoi(fields[0])}
  }
 }
 if p.PPID<0||p.RealUID<0{return ProcState{},errors.New("Linux process status incomplete")}
 exe,err:=os.Readlink(fmt.Sprintf("/proc/%d/exe",pid))
 if err!=nil||!strings.HasPrefix(exe,"/"){return ProcState{},errors.New("process executable unavailable")}
 p.Executable=exe
 return p,nil
}
// MatchSSHDAncestor binds kernel SO_PEERCRED pid -> actual root-owned sshd
// ancestor -> the exact daemon PID that produced an accepted-publickey
// journal record. A password-authenticated different session cannot present
// the same parent chain.
//
// This is ONE piece of future attestation: a root helper must obtain the PID
// through SO_PEERCRED, not HTTP payload or user environment, and independently
// check the exact journald record and nonce.
func MatchSSHDAncestor(peerPID int,auth Event,reader ProcessReader)error{
 if peerPID<=1||auth.PID<=1||!trustedSSHDExecutable(auth.SourcePath){
  return errors.New("missing trusted SSH process context")
 }
 if reader==nil{return errors.New("process reader unavailable")}
 seen:=map[int]bool{}
 pid:=peerPID
 for depth:=0;depth<32&&pid>1;depth++{
  if seen[pid]{return errors.New("process ancestry cycle")}
  seen[pid]=true
  proc,err:=reader(pid)
  if err!=nil||proc.PID!=pid||proc.PPID<0||proc.PPID==pid{
   return errors.New("untrusted or raced Linux parent process")
  }
  if pid==auth.PID{
   if proc.RealUID!=0||proc.Executable!=auth.SourcePath{
    return errors.New("SSH journal PID is not the trusted root daemon")
   }
   return nil
  }
  if proc.PPID==0{return errors.New("SSH parent process not found")}
  pid=proc.PPID
 }
 return errors.New("SSH accepted event is not an ancestor of the verifier session")
}
