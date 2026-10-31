//go:build linux

package sshproof

import (
 "crypto/sha256"
 "crypto/subtle"
 "encoding/base64"
 "encoding/hex"
 "errors"
)

// TrustedPeer values must come from SO_PEERCRED on a dedicated, unprivileged,
// challenge-only Unix socket. They cannot come from arbitrary JSON claims.
type TrustedPeer struct {
 PID int
 RealUID int
}

// VerifyLocalSSHProof checks an issued nonce, kernel peer credentials,
// exact daemon ancestry and real accepted-publickey event metadata.
//
// The root helper must independently obtain the event from local journald
// and resolve the peer PID through SO_PEERCRED. DO NOT call this with browser
// supplied events/credentials or treat it as sufficient without challenge
// lifecycle, signed server attestation and Cloudflare one-time consumption.
func VerifyLocalSSHProof(peer TrustedPeer,expectedUID int,nonce,nonceHashHex string,
 challenge Challenge,acceptedEvent Event,readProcess ProcessReader)error{
 if peer.PID<=1||peer.RealUID<0||peer.RealUID!=expectedUID{
  return errors.New("SSH verifier process UID or PID mismatch")
 }
 if len(nonce)!=43||len(nonceHashHex)!=64{
  return errors.New("malformed one-time verification nonce")
 }
 raw,err:=base64.RawURLEncoding.DecodeString(nonce)
 if err!=nil||len(raw)!=32{
  return errors.New("invalid verification nonce entropy")
 }
 hash,err:=hex.DecodeString(nonceHashHex)
 if err!=nil||len(hash)!=sha256.Size{
  return errors.New("invalid stored challenge digest")
 }
 expectedHash:=sha256.Sum256([]byte(nonce))
 if subtle.ConstantTimeCompare(hash,expectedHash[:])!=1{
  return errors.New("SSH login verification challenge mismatch")
 }
 process,err:=readProcess(peer.PID)
 if err!=nil||process.PID!=peer.PID||process.RealUID!=peer.RealUID{
  return errors.New("kernel peer UID not confirmed by /proc")
 }
 if err:=Match(acceptedEvent,challenge);err!=nil{return err}
 if err:=MatchSSHDAncestor(peer.PID,acceptedEvent,readProcess);err!=nil{return err}
 return nil
}
