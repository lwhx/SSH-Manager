package sshhelper

import (
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
)
type ManualOperationReceipt struct{
 V int `json:"v"`
 NodeID string `json:"node_id"`
 OperationID string `json:"operation_id"`
 Action string `json:"action"`
 ResultCode string `json:"result_code"`
 ExpectedRevision string `json:"expected_revision"`
 DetailSHA256 string `json:"detail_sha256"`
 ExecutedAt int64 `json:"executed_at"`
 NoSSHWrite bool `json:"no_ssh_write,omitempty"`
}
type SignedManualReceipt struct{
 Payload string `json:"payload"`
 Signature string `json:"signature"`
}
// A no-write proof is permitted only for failures emitted before the SSH
// mutator is invoked. Unknown/post-write failures must remain unresolved.
// Keep this list synchronized with packages/protocol/src/manual.ts.
func manualNoWriteFailure(code string)bool{
 switch code{
 case "SSHD_INSPECTION_FAILED","UNSUPPORTED_SSH_POLICY","POLICY_REVISION_MISMATCH",
  "MANUAL_ACTOR_REQUIRED","MANUAL_PAYLOAD_INVALID","MANUAL_NODE_CONFIRMATION_REQUIRED",
  "PASSWORD_DISABLE_LOCAL_LOCKED","FRESH_VERIFIED_LOGIN_REQUIRED",
  "MANUAL_RESTORE_LOCAL_LOCKED","RESCUE_LOCAL_LOCKED","RESCUE_KEY_SCOPE_MISMATCH",
  "RESCUE_KEY_INVALID","RESCUE_LOGIN_USER_INVALID":
  return true
 }
 return false
}

// Only rejections BEFORE the daily SSH key writer may attest no SSH change.
// A failed snapshot, partial append, fsync error or file verification after
// InstallDaily begins is never proof of no write.
func dailyNoWriteFailure(code string)bool{
 switch code{
 case "SSHD_INSPECTION_FAILED","UNSUPPORTED_SSH_POLICY",
  "DAILY_INSTALL_DISABLED","POLICY_REVISION_MISMATCH","INVALID_KEY_PAYLOAD",
  "USER_OR_KEY_SCOPE_MISMATCH","INVALID_DAILY_KEY","KEY_FINGERPRINT_MISMATCH",
  "TARGET_USER_MISSING","INVALID_USER_ID","INVALID_GROUP_ID",
  "TARGET_USER_MISMATCH":
  return true
 }
 return false
}
// signManualReceipt binds a terminal result (including daily key install)
// to the pinned Root-only key. The Agent can relay but cannot forge it.
// Failed signed receipts attest that the command never reached SSH writes.
func (h *Handler) signManualReceipt(cmd Command, result Result)Result{
 if !(isManualSSHAction(cmd.Action)||cmd.Action=="ssh.daily.install")||
  len(h.ProofSigningKey)!=ed25519.PrivateKeySize{
  return fail("ROOT_MANUAL_RECEIPT_UNAVAILABLE",nil)
 }
 if !result.OK{
  safe:=manualNoWriteFailure(result.Code)
  if cmd.Action=="ssh.daily.install"{safe=dailyNoWriteFailure(result.Code)}
  if !safe{return result}
  // Do not expose original stderr, paths, or account information.
  result.Detail=map[string]string{"code":result.Code}
 }
 raw,err:=json.Marshal(result.Detail)
 if err!=nil||len(raw)>4096{return fail("ROOT_MANUAL_RESULT_TOO_LARGE",nil)}
 digest:=sha256.Sum256(raw)
 receipt:=ManualOperationReceipt{
  V:1,NodeID:cmd.NodeID,OperationID:cmd.ID,Action:cmd.Action,
  ResultCode:result.Code,ExpectedRevision:cmd.ExpectedRevision,
  DetailSHA256:hex.EncodeToString(digest[:]),ExecutedAt:h.Clock().Unix(),
  NoSSHWrite:!result.OK,
 }
 if receipt.ExecutedAt<cmd.IssuedAt-10||receipt.ExecutedAt>cmd.ExpiresAt{
  return fail("ROOT_MANUAL_RECEIPT_OUTSIDE_COMMAND_WINDOW",errors.New("execution outside signed command lifetime"))
 }
 body,err:=json.Marshal(receipt)
 if err!=nil{return fail("ROOT_MANUAL_RECEIPT_UNAVAILABLE",err)}
 signed:=SignedManualReceipt{Payload:string(body),
  Signature:base64.RawURLEncoding.EncodeToString(ed25519.Sign(h.ProofSigningKey,body))}
 result.Detail=map[string]any{"result":result.Detail,"root_receipt":signed}
 return result
}
