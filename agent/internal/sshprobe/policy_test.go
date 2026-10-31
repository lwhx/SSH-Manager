package sshprobe
import (
 "strings"
 "testing"
)
const normal = "pubkeyauthentication yes\npasswordauthentication yes\nkbdinteractiveauthentication yes\npermitrootlogin prohibit-password\nauthorizedkeysfile .ssh/authorized_keys\nauthenticationmethods any\n"
func TestEffectivePolicy(t *testing.T){
 p,err:=ParseEffective(normal)
 if err!=nil{t.Fatal(err)}
 if err:=p.DailyKeyEligibility("root");err!=nil{t.Fatal(err)}
 if !p.PasswordAuthentication||!p.KeyboardInteractive{t.Fatal("existing password channels were lost")}
 if p.Revision==""{t.Fatal("missing policy revision")}
}
func TestRejectIncompatiblePolicies(t *testing.T){
 bad:=[]string{
  strings.Replace(normal,"pubkeyauthentication yes","pubkeyauthentication no",1),
  strings.Replace(normal,"permitrootlogin prohibit-password","permitrootlogin no",1),
  strings.Replace(normal,"authorizedkeysfile .ssh/authorized_keys","authorizedkeysfile /tmp/keys",1),
  strings.Replace(normal,"authenticationmethods any","authenticationmethods publickey,password",1),
 }
 for i,txt:=range bad{
  p,err:=ParseEffective(txt)
  if err!=nil{t.Fatalf("case %d: %v",i,err)}
  if err:=p.DailyKeyEligibility("root");err==nil{t.Fatalf("unsafe policy accepted case %d",i)}
 }
}
func TestRejectDuplicateAndMissing(t *testing.T){
 if _,err:=ParseEffective(normal+"pubkeyauthentication no\n");err==nil{t.Fatal("duplicate accepted")}
 if _,err:=ParseEffective(strings.Replace(normal,"authenticationmethods any\n","",1));err==nil{t.Fatal("missing accepted")}
}

func TestAcceptsTwoStandardOpenSSHKeyLocations(t *testing.T){
 output:=strings.Replace(normal,"authorizedkeysfile .ssh/authorized_keys","authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2",1)
 p,err:=ParseEffective(output)
 if err!=nil{t.Fatal(err)}
 if err:=p.DailyKeyEligibility("root");err!=nil{t.Fatalf("standard authorized_keys2 fallback rejected: %v",err)}
}
