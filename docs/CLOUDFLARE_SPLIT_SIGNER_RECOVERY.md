# Cloudflare split-Worker signing key recovery (Staging only)

This applies when code is deployed to `ssh-manager`, D1 is `ssh-manager-staging`, and the previous build created an extra Worker `ssh-manager-staging` to hold `COMMAND_PRIVATE_KEY`.

Keep the D1 database and its six completed migrations. Cloudflare secrets cannot be read back in plaintext.

## Controlled repair

1. Confirm in Workers & Pages that the connected Worker `ssh-manager` has DB and NODE_SESSIONS bindings and both intended custom domains. Cloudflare Access protects ONLY the Control hostname.
2. In `ssh-manager` -> Settings -> Builds -> Build variables and secrets, add a **temporary plain-text Build variable**:

   - Name: `SSH_MANAGER_RECOVER_EMPTY_STAGING`
   - Value: `CONFIRM_EMPTY_STAGING_SIGNER_REPAIR`

3. Once GitHub PR #5 has merged to main, retry the Cloudflare build. The new script re-checks the actual Cloudflare Worker, D1 UUID and root signing public key, then runs a read-only query on eight VPS identity/operation tables. If any contain rows or cannot be validated, recovery fails without rotating the signer.
4. Only on a successful result (`RECOVERY OK`), immediately **remove SSH_MANAGER_RECOVER_EMPTY_STAGING** from Cloudflare Build variables. Normal future updates reuse the existing signer.
5. Confirm `COMMAND_PRIVATE_KEY` exists as a Secret on `ssh-manager`. Verify the Control Access login, Agent device-health endpoint, and that the Agent hostname rejects /api/v1/health with 404.
6. If everything is healthy, you may manually clean up the **extra Worker** `ssh-manager-staging` after verifying it has no intended routes. Never delete the **D1 database** `ssh-manager-staging`.

This only rotates the Cloudflare command-signing key in a provably empty Staging deployment. No VPS SSH keys, device identities, D1 rows or SSH settings are changed.

If the build stops after deploying a new public key but before uploading the matching Secret, keep VPS disconnected and investigate before retrying.
