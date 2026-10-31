//go:build linux

package sshproof

import "testing"

func TestKernelPeerLineageMatchesExactlyJournalSSHD(t *testing.T){
 event:=Event{PID:100,SourcePath:"/usr/sbin/sshd"}
 processes:=map[int]ProcState{
  300:{PID:300,PPID:200,RealUID:1000,Executable:"/usr/local/bin/ssh-manager-prove"},
  200:{PID:200,PPID:100,RealUID:1000,Executable:"/bin/sh"},
  100:{PID:100,PPID:1,RealUID:0,Executable:"/usr/sbin/sshd"},
 }
 reader:=func(pid int)(ProcState,error){return processes[pid],nil}
 if err:=MatchSSHDAncestor(300,event,reader);err!=nil{t.Fatal(err)}
}
func TestRejectsPasswordSessionOrFakeRootProcess(t *testing.T){
 baseline:=Event{PID:100,SourcePath:"/usr/sbin/sshd"}
 for name,change:=range map[string]func(map[int]ProcState,*Event){
  "separate ssh session":func(p map[int]ProcState,e *Event){e.PID=102},
  "wrong executable":func(p map[int]ProcState,e *Event){x:=p[100];x.Executable="/usr/bin/logger";p[100]=x},
  "untrusted uid":func(p map[int]ProcState,e *Event){x:=p[100];x.RealUID=1000;p[100]=x},
  "missing ancestor":func(p map[int]ProcState,e *Event){x:=p[200];x.PPID=1;p[200]=x},
  "cycle":func(p map[int]ProcState,e *Event){x:=p[200];x.PPID=300;p[200]=x},
  "unknown daemon":func(p map[int]ProcState,e *Event){e.SourcePath="/tmp/fake-sshd"},
 }{
  t.Run(name,func(t *testing.T){
   processes:=map[int]ProcState{
    300:{PID:300,PPID:200,RealUID:1000,Executable:"/usr/local/bin/ssh-manager-prove"},
    200:{PID:200,PPID:100,RealUID:1000,Executable:"/bin/sh"},
    100:{PID:100,PPID:1,RealUID:0,Executable:"/usr/sbin/sshd"},
   }
   event:=baseline;change(processes,&event)
   reader:=func(pid int)(ProcState,error){return processes[pid],nil}
   if err:=MatchSSHDAncestor(300,event,reader);err==nil{t.Fatal("accepted forged SSH daemon ancestry")}
  })
 }
}
