package main

import (
 "errors"
 "testing"
)

func TestGatewayStructuredTerminalProofResponses(t *testing.T){
 for _,code:=range []string{
  "CHALLENGE_NOT_ACTIVE",
  "CHALLENGE_CONTEXT_CHANGED",
  "PROOF_ALREADY_USED_OR_CONTEXT_CHANGED",
 }{
  t.Run(code,func(t *testing.T){
   err:=parseGatewayHTTPError(409,[]byte(`{"error":"`+code+`"}`))
   got,terminal:=permanentProofRejection(err)
   if !terminal||got!=code{t.Fatalf("terminal rejection lost: %v %v",got,err)}
  })
 }
}
func TestTransientOrUnknownGatewayResponseDoesNotDiscardProof(t *testing.T){
 cases:=[]struct{status int;code string}{
  {401,"UNAUTHORIZED"}, // Device identity could be restored
  {403,"NODE_ROOT_PROOF_KEY_NOT_PINNED"}, // Owner may pin key
  {403,"ROOT_SSH_PROOF_SIGNATURE_OR_CONTEXT_INVALID"},
  {404,"NOT_FOUND"}, // Wrong deployment/route
  {409,"REPLAY"}, // Device request nonce replay
  {409,"INVALID_STATUS_TRANSITION"},
  {409,"CHALLENGE_PREPARATION_UNCONFIRMED"},
  {409,"ATOMIC_PROOF_TRANSITION_NOT_COMPLETED"},
  {429,"RATE_LIMIT"},
  {500,"INTERNAL_ERROR"},
  {503,"GATEWAY_UNAVAILABLE"},
 }
 for _,tc:=range cases{
  err:=parseGatewayHTTPError(tc.status,[]byte(`{"error":"`+tc.code+`"}`))
  if reason,terminal:=permanentProofRejection(err);terminal{
   t.Fatalf("retryable status %d/%s would quarantine proof: %s",tc.status,tc.code,reason)
  }
 }
 if _,terminal:=permanentProofRejection(errors.New("network unavailable"));terminal{
  t.Fatal("network outage would discard SSH proof")
 }
}
func TestGatewayResponseCodeIsSanitized(t *testing.T){
 for _,body:=range [][]byte{
  []byte(`{"error":"value
PRIVATE_KEY"}`),
  []byte(`{"error":"unknown-lower-case"}`),
  []byte("not-json"),
  []byte(`{"error":"CHALLENGE_NOT_ACTIVE
secret"}`),
 }{
  err:=parseGatewayHTTPError(409,body)
  var httpErr *GatewayHTTPError
  if !errors.As(err,&httpErr)||httpErr.Code!="UNRECOGNIZED_GATEWAY_ERROR"{
   t.Fatalf("unsanitized server error: %v",err)
  }
  if _,terminal:=permanentProofRejection(err);terminal{t.Fatal("unknown 409 quarantined proof")}
 }
}
