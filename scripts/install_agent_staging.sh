#!/usr/bin/env bash
# SSH Manager Staging ONLY: enroll the unprivileged outbound Agent.
# Does not change sshd, authorized_keys, password authentication, or SSH policies.
set +x
set -Eeuo pipefail
umask 077

fail() { printf 'ERROR: %s\n' "$1" >&2; exit 1; }
usage() {
  cat <<'USAGE'
Usage: sudo bash install_agent_staging.sh --node-id UUID --gateway HTTPS_ORIGIN --revision FULL_GIT_SHA

Staging test VPS ONLY. Requires Linux with systemd, curl, tar and Go >= 1.23.
Installs the non-root Agent and the inactive Root Helper binaries, then asks
for a ten-minute pairing token interactively. Token is never passed in argv.
Does NOT change SSH configuration, disable passwords, or start Root Helper.
USAGE
}
NODE=""
GATEWAY=""
REV=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --node-id) shift; [ "$#" -gt 0 ] || fail "--node-id needs a value"; NODE="$1" ;;
    --gateway) shift; [ "$#" -gt 0 ] || fail "--gateway needs a value"; GATEWAY="$1" ;;
    --revision) shift; [ "$#" -gt 0 ] || fail "--revision needs a value"; REV="$1" ;;
    -h|--help) usage; exit 0 ;;
    *) fail "Unknown argument: $1" ;;
  esac
  shift
done

[ "$(id -u)" -eq 0 ] || fail "Run with sudo/root on a disposable Staging VPS"
[ "$(uname -s)" = Linux ] || fail "Linux is required"
case "$(uname -m)" in x86_64|aarch64) ;; *) fail "Only amd64 and arm64 are supported" ;; esac
[ -d /run/systemd/system ] || fail "systemd is required"
[ -r /etc/os-release ] || fail "Unsupported system (missing /etc/os-release)"
. /etc/os-release
case "$ID" in debian|ubuntu) ;; *) fail "Only Debian and Ubuntu Staging are supported" ;; esac

[[ "$NODE" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || fail "Invalid Node UUID"
[[ "$GATEWAY" =~ ^https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || fail "Expected an HTTPS Agent Gateway origin with no path, port or query"
[[ "$REV" =~ ^[a-f0-9]{40}$ ]] || fail "A pinned 40-character Git commit is required"
[ -r /dev/tty ] || fail "An interactive terminal is required to enter the token safely"

# sudo may omit /usr/local/go/bin from PATH even when Go is installed.
if ! command -v go >/dev/null 2>&1 && [ -x /usr/local/go/bin/go ]; then
  export PATH="/usr/local/go/bin:$PATH"
fi
for cmd in curl tar go install systemctl useradd groupadd getent; do
  command -v "$cmd" >/dev/null 2>&1 || fail "Missing prerequisite: $cmd"
done
GO_VER="$(go env GOVERSION)"
[[ "$GO_VER" =~ ^go([0-9]+)\.([0-9]+) ]] || fail "Cannot check Go version"
GO_MAJOR="$(printf '%s' "$GO_VER" | sed -E 's/^go([0-9]+)\..*/\1/')"
GO_MINOR="$(printf '%s' "$GO_VER" | sed -E 's/^go[0-9]+\.([0-9]+).*/\1/')"
if [ "$GO_MAJOR" -lt 1 ] || { [ "$GO_MAJOR" -eq 1 ] && [ "$GO_MINOR" -lt 23 ]; }; then
  fail "Go >= 1.23 required. Install Go from https://go.dev/dl/ before retrying"
fi

for path in /etc/ssh-manager/agent.json /etc/systemd/system/ssh-manager-agent.service \
  /usr/local/bin/ssh-manager-agent /usr/local/libexec/ssh-manager-helper \
  /usr/local/bin/ssh-manager-prove; do
  [ ! -e "$path" ] || fail "Existing SSH Manager installation at $path; refusing to overwrite"
done

printf '\nSSH Manager: isolated Staging VPS Agent enrollment\n'
printf 'Target node: %s\nGateway: %s\nSource commit: %s\n' "$NODE" "$GATEWAY" "$REV"
printf 'No sshd, authorized_keys, password authentication or system login setting will be changed.\n'
IFS= read -r -p "Type YES to confirm this is a disposable test VPS: " CONFIRM < /dev/tty || fail "Confirmation unavailable"
[ "$CONFIRM" = YES ] || fail "Cancelled"

TMP="$(mktemp -d)"
TOKEN=""
trap 'unset TOKEN; rm -rf -- "$TMP"' EXIT
mkdir -p "$TMP/source" "$TMP/bin"
curl -fsSL --proto '=https' --tlsv1.2 --retry 2 \
  "https://codeload.github.com/lwhx/SSH-Manager/tar.gz/$REV" -o "$TMP/repo.tar.gz" \
  || fail "Cannot download pinned repository revision"
tar -xzf "$TMP/repo.tar.gz" --strip-components=1 -C "$TMP/source"
[ -f "$TMP/source/agent/go.mod" ] || fail "Pinned archive does not contain the Agent sources"
[ -f "$TMP/source/agent/ssh-manager-agent.service" ] || fail "Missing Agent systemd unit"

(
  cd "$TMP/source/agent"
  CGO_ENABLED=0 go build -trimpath -o "$TMP/bin/ssh-manager-agent" .
  CGO_ENABLED=0 go build -trimpath -o "$TMP/bin/ssh-manager-helper" ./cmd/ssh-manager-helper
  CGO_ENABLED=0 go build -trimpath -o "$TMP/bin/ssh-manager-prove" ./cmd/ssh-manager-prove
) || fail "Go Agent build failed (check network and Go toolchain)"

if ! getent group ssh-manager >/dev/null; then groupadd --system ssh-manager; fi
if ! id -u ssh-manager >/dev/null 2>&1; then
  useradd --system --gid ssh-manager --home-dir /nonexistent --shell /usr/sbin/nologin ssh-manager
fi
[ "$(id -gn ssh-manager)" = ssh-manager ] || fail "Unexpected service-user group"
install -d -o root -g ssh-manager -m 0750 /etc/ssh-manager
install -d -o root -g root -m 0755 /usr/local/libexec
install -o root -g root -m 0755 "$TMP/bin/ssh-manager-agent" /usr/local/bin/ssh-manager-agent
install -o root -g root -m 0755 "$TMP/bin/ssh-manager-prove" /usr/local/bin/ssh-manager-prove
install -o root -g root -m 0755 "$TMP/bin/ssh-manager-helper" /usr/local/libexec/ssh-manager-helper
install -o root -g root -m 0644 "$TMP/source/agent/ssh-manager-agent.service" /etc/systemd/system/ssh-manager-agent.service
# Helper is installed but intentionally NOT configured, enabled, or started.
install -o root -g root -m 0644 "$TMP/source/agent/ssh-manager-helper.service" /etc/systemd/system/ssh-manager-helper.service

printf '\nAgent binaries installed. Open the admin panel and generate a FRESH 10-minute token now.\n'
printf 'The token will NOT be echoed or saved in command history.\n'
IFS= read -r -s -p "Paste the pairing token: " TOKEN < /dev/tty || fail "Token input cancelled"
printf '\n' > /dev/tty
[[ "$TOKEN" =~ ^[a-zA-Z0-9_-]{43}$ ]] || fail "Invalid pairing token format"
printf '%s\n' "$TOKEN" | /usr/local/bin/ssh-manager-agent \
  -mode pair -gateway "$GATEWAY" -node "$NODE" -token-stdin \
  -config /etc/ssh-manager/agent.json || fail "Pairing failed. Do NOT reuse the token; inspect the Agent gateway first."
unset TOKEN

systemctl daemon-reload
systemctl enable --now ssh-manager-agent.service || fail "Agent service failed to start; inspect journalctl -u ssh-manager-agent -n 60"
systemctl is-active --quiet ssh-manager-agent.service || fail "Agent is not running"
printf '\nAgent paired and service is running. Refresh the node in SSH Manager; online status follows its first heartbeat.\n'
printf 'Root Helper remains disabled until you explicitly configure and validate its root-owned configuration.\n'
printf 'Status: systemctl status ssh-manager-agent.service\n'
