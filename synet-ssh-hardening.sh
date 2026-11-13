#!/usr/bin/env bash
# Synet SSH Hardening v1.1 — Ubuntu 22.04/24.04/26.04, OpenSSH + systemd.
# Usage: sudo bash synet-ssh-hardening.sh
# After connecting on the new port as the new user, run:
#   sudo env SYNET_CONNECTED_PORT="${SSH_CONNECTION##* }" /usr/local/sbin/synet-ssh-guard --confirm
# If not confirmed within 15 minutes, original SSH settings are restored.
set -Eeuo pipefail
umask 077

CONTROL=/usr/local/sbin/synet-ssh-guard
STATE_DIR=/var/lib/synet-ssh-guard
STATE_FILE=$STATE_DIR/state
CONFIG=/etc/ssh/sshd_config.d/00-synet-ssh-hardening.conf
ROLLBACK_UNIT=synet-ssh-guard-rollback
TIMEOUT=15min
SOCKET_DROPIN=/etc/systemd/system/ssh.socket.d/99-synet-ssh.conf

configure_socket_ports() {
  # When ssh.socket is active, its ListenStream entries can override sshd Port.
  [[ "$SOCKET_ACTIVE" == 1 ]] || return 0
  install -d -m 755 /etc/systemd/system/ssh.socket.d
  {
    printf '[Socket]\nListenStream=\n'
    for port in "$@"; do printf 'ListenStream=%s\n' "$port"; done
  } > "$SOCKET_DROPIN"
  chmod 644 "$SOCKET_DROPIN"
}

say()  { printf '\n\033[1;36m%s\033[0m\n' "$*"; }
warn() { printf '\n\033[1;33mWARNING: %s\033[0m\n' "$*" >&2; }
die()  { printf '\nERROR: %s\n' "$*" >&2; exit 1; }
require_root() { [[ ${EUID} -eq 0 ]] || die 'Run with sudo/root.'; }

load_state() {
  [[ -f "$STATE_FILE" ]] || die 'No pending SSH setup found.'
  # State is written by root under 0700 directory; values are constrained before writing.
  # shellcheck disable=SC1090
  source "$STATE_FILE"
}

restore_config() {
  load_state
  if [[ "$HAD_CONFIG" == 1 ]]; then
    cp -a "$STATE_DIR/previous-config" "$CONFIG"
  else
    rm -f -- "$CONFIG"
  fi
  if [[ -f "$STATE_DIR/previous-ssh-socket-dropin" ]]; then
    install -d -m 755 /etc/systemd/system/ssh.socket.d
    cp -a "$STATE_DIR/previous-ssh-socket-dropin" "$SOCKET_DROPIN"
  else
    rm -f "$SOCKET_DROPIN"
  fi
  if [[ "$UFW_ADDED" == 1 ]] && command -v ufw >/dev/null 2>&1; then
    ufw --force delete allow "${NEW_PORT}/tcp" >/dev/null 2>&1 || true
  fi
  systemctl daemon-reload || true
  if [[ "$SOCKET_ACTIVE" == 1 ]]; then
    systemctl restart ssh.socket || true
  fi
  systemctl reload ssh.service 2>/dev/null || true
}

rollback() {
  require_root
  if [[ ! -f "$STATE_FILE" ]]; then
    printf 'No pending changes to roll back.\n'
    exit 0
  fi
  warn 'Confirmation not received, restoring previous SSH settings.'
  restore_config
  rm -f "$STATE_FILE"
  printf 'Original SSH settings restored. Existing user and public key were not deleted.\n'
}

finish() {
  require_root
  load_state
  [[ "${SYNET_CONNECTED_PORT:-}" == "$NEW_PORT" ]] || die \
    "Confirm only from a NEW SSH session connected to port $NEW_PORT, using: sudo env SYNET_CONNECTED_PORT=\"\${SSH_CONNECTION##* }\" $CONTROL --confirm"
  say "New SSH session validated on port $NEW_PORT. Closing old SSH ports."
  # Keep only the designated SSH port in our snippet. The original sshd_config is untouched.
  sed -i -E '/^Port [0-9]+$/d' "$CONFIG"
  { printf 'Port %s\n' "$NEW_PORT"; cat "$CONFIG"; } > "$STATE_DIR/finished-config"
  install -m 600 "$STATE_DIR/finished-config" "$CONFIG"
  sshd -t || { restore_config; die 'SSH configuration invalid; old settings restored.'; }
  configure_socket_ports "$NEW_PORT"
  systemctl daemon-reload
  if [[ "$SOCKET_ACTIVE" == 1 ]]; then systemctl restart ssh.socket; fi
  systemctl reload ssh.service 2>/dev/null || true
  if ! ss -Hlt "( sport = :$NEW_PORT )" | grep -q .; then
    restore_config
    die "New port $NEW_PORT is not listening; old settings restored."
  fi
  read -r -a PREVIOUS_PORTS <<< "$OLD_PORTS_JOINED"
  for port in "${PREVIOUS_PORTS[@]}"; do
    [[ "$port" == "$NEW_PORT" ]] && continue
    if ss -Hlt "( sport = :$port )" | grep -q .; then
      restore_config
      die "Old port $port still listens (another Port/ListenStream directive may override ours); previous SSH config restored."
    fi
  done
  systemctl stop "${ROLLBACK_UNIT}.timer" 2>/dev/null || true
  # Old firewall allow rules are intentionally left in place: deleting shared rules may break other services.
  rm -f "$STATE_FILE"
  say "SSH protection enabled. SSH port: $NEW_PORT. Root and password SSH access disabled."
  warn 'Old firewall allow rules may remain. Check UFW/provider firewall and ensure no unintended SSH listener remains on the old port.'
}

if [[ ${1:-} == '--rollback' ]]; then rollback; exit 0; fi
if [[ ${1:-} == '--confirm' ]]; then finish; exit 0; fi
[[ $# == 0 ]] || die 'Usage: sudo bash synet-ssh-hardening.sh [--confirm|--rollback]'
require_root

# If an error occurs after the state file has been created, restore the
# previous SSH settings instead of leaving an unconfirmed configuration.
cleanup_on_exit() {
  local rc=$?
  [[ -n "${TMP_KEY:-}" ]] && rm -f -- "$TMP_KEY"
  if (( rc != 0 )) && [[ -f "$STATE_FILE" ]]; then
    warn 'Setup failed; restoring SSH configuration.'
    restore_config || warn 'Automatic restoration failed; use your VPS console.'
    systemctl stop "${ROLLBACK_UNIT}.timer" 2>/dev/null || true
    rm -f "$STATE_FILE"
  fi
}
trap cleanup_on_exit EXIT

command -v sshd >/dev/null 2>&1 || die 'OpenSSH server is not installed.'
command -v systemctl >/dev/null 2>&1 || die 'systemd is required.'
command -v ssh-keygen >/dev/null 2>&1 || die 'ssh-keygen is required.'
command -v ss >/dev/null 2>&1 || die 'iproute2/ss is required.'
command -v systemd-run >/dev/null 2>&1 || die 'systemd-run is required for automatic rollback.'
[[ -f /etc/ssh/sshd_config ]] || die '/etc/ssh/sshd_config is missing.'
[[ ! -f "$STATE_FILE" ]] || die "An SSH setup is already pending. Confirm or allow rollback first."

say 'Synet — automatic SSH hardening'
printf 'The script will ask for username, password and ONE authorized_keys public key.\n'
printf 'It will generate a new SSH port and temporarily keep existing ports for rollback.\n'
read -r -p 'Username (e.g. lendry): ' USERNAME
[[ "$USERNAME" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die 'Invalid username (lowercase letters, numbers, _ and - only).'
[[ "$USERNAME" != root ]] || die 'Do not use root.'
read -r -s -p 'Password for this user (SSH password login will be disabled): ' PASSWORD
printf '\n'
[[ -n "$PASSWORD" && ${#PASSWORD} -ge 8 ]] || die 'Password must be at least 8 characters.'
read -r -p 'Paste the SSH PUBLIC key (ssh-ed25519 AAAA...): ' PUBLIC_KEY
[[ "$PUBLIC_KEY" == ssh-* || "$PUBLIC_KEY" == ecdsa-* || "$PUBLIC_KEY" == sk-* ]] || die 'Expected one PUBLIC key line starting ssh-ed25519, ssh-rsa, ecdsa-..., etc.'
[[ "$PUBLIC_KEY" != *$'\r'* && "$PUBLIC_KEY" != *$'\n'* ]] || die 'Key must be on one line.'

TMP_KEY=$(mktemp)
printf '%s\n' "$PUBLIC_KEY" > "$TMP_KEY"
ssh-keygen -lf "$TMP_KEY" >/dev/null 2>&1 || die 'Public SSH key is invalid.'

# Safety checks before changing SSH configuration.
sshd -t || die 'Current sshd_config is already invalid; refusing to proceed.'
if systemctl is-active --quiet ssh.socket; then
  SOCKET_ACTIVE=1
else
  SOCKET_ACTIVE=0
fi
if [[ "$SOCKET_ACTIVE" == 1 ]] && grep -qsHE '^[[:space:]]*ListenStream[[:space:]]*=' \
    /etc/systemd/system/ssh.socket.d/*.conf 2>/dev/null; then
  die 'ssh.socket has a custom ListenStream override. Refusing to change ports automatically.'
fi

# Collect effective ports. Current sshd_config is otherwise not edited.
mapfile -t OLD_PORTS < <(sshd -T | awk '$1 == "port" {print $2}' | sort -nu)
((${#OLD_PORTS[@]})) || OLD_PORTS=(22)
# Include port 22 as an explicit emergency fallback only if it already listens.
# Random high port must not be in use.
NEW_PORT=${SYNET_SSH_PORT:-}
if [[ -n "$NEW_PORT" ]]; then
  [[ "$NEW_PORT" =~ ^[0-9]{4,5}$ ]] && (( NEW_PORT >= 1024 && NEW_PORT <= 65535 )) || die 'Invalid SYNET_SSH_PORT.'
  ss -Hlt "( sport = :$NEW_PORT )" | grep -q . && die "Port $NEW_PORT is already in use."
else
  for _ in {1..30}; do
    NEW_PORT=$(shuf -i 20000-49999 -n 1)
    if ! ss -Hlt "( sport = :$NEW_PORT )" | grep -q .; then break; fi
  done
  ss -Hlt "( sport = :$NEW_PORT )" | grep -q . && die 'Unable to select a free port.'
fi

if ! id "$USERNAME" &>/dev/null; then
  say "Creating user: $USERNAME"
  useradd -m -s /bin/bash "$USERNAME"
else
  say "User already exists: $USERNAME (updating password, adding public key)"
fi
printf '%s:%s\n' "$USERNAME" "$PASSWORD" | chpasswd
unset PASSWORD
usermod -aG sudo "$USERNAME"
HOME_DIR=$(getent passwd "$USERNAME" | cut -d: -f6)
GROUP=$(id -gn "$USERNAME")
[[ -d "$HOME_DIR" && "$HOME_DIR" != / ]] || die 'Unsafe or missing home directory.'
install -d -m 700 -o "$USERNAME" -g "$GROUP" "$HOME_DIR/.ssh"
AUTHORIZED="$HOME_DIR/.ssh/authorized_keys"
touch "$AUTHORIZED"
chown "$USERNAME:$GROUP" "$AUTHORIZED"
chmod 600 "$AUTHORIZED"
if ! grep -Fxq -- "$PUBLIC_KEY" "$AUTHORIZED"; then
  printf '%s\n' "$PUBLIC_KEY" >> "$AUTHORIZED"
fi
unset PUBLIC_KEY

install -d -m 700 "$STATE_DIR"
HAD_CONFIG=0
if [[ -e "$CONFIG" ]]; then
  HAD_CONFIG=1
  cp -a "$CONFIG" "$STATE_DIR/previous-config"
fi
if [[ -e /etc/systemd/system/ssh.socket.d/99-synet-ssh.conf ]]; then
  cp -a /etc/systemd/system/ssh.socket.d/99-synet-ssh.conf "$STATE_DIR/previous-ssh-socket-dropin"
fi
UFW_ADDED=0
# If UFW is active, ensure it permits the new port BEFORE we reconfigure sshd.
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then
  if ! ufw status | grep -Eq "^${NEW_PORT}/tcp[[:space:]]+ALLOW"; then
    ufw allow "${NEW_PORT}/tcp" comment 'synet-ssh-new-port'
    UFW_ADDED=1
  fi
fi

# Record safe root-written values for eventual rollback. No password or key is saved here.
{
  printf 'NEW_PORT=%q\n' "$NEW_PORT"
  printf 'SOCKET_ACTIVE=%q\n' "$SOCKET_ACTIVE"
  printf 'HAD_CONFIG=%q\n' "$HAD_CONFIG"
  printf 'UFW_ADDED=%q\n' "$UFW_ADDED"
  printf 'OLD_PORTS_JOINED=%q\n' "${OLD_PORTS[*]}"
} > "$STATE_FILE"
chmod 600 "$STATE_FILE"

# Install control command for confirmation/automatic rollback.
# Run the installer from a real downloaded file (not `curl | bash`).
[[ -f "$0" && -r "$0" ]] || die 'Installer must be run from a downloaded file, not a pipe.'
install -m 700 -- "$(readlink -f "$0")" "$CONTROL"

# Safe first phase: keep the previous effective SSH ports until a new SSH login is verified.
{
  printf '# Managed by Synet SSH Hardening. Do not edit before confirmation.\n'
  for p in "${OLD_PORTS[@]}"; do printf 'Port %s\n' "$p"; done
  printf 'Port %s\n' "$NEW_PORT"
  printf '%s\n' \
    'PermitRootLogin no' \
    'DenyUsers root' \
    'PubkeyAuthentication yes' \
    'PasswordAuthentication no' \
    'KbdInteractiveAuthentication no' \
    'AuthenticationMethods publickey' \
    'PermitEmptyPasswords no' \
    'MaxAuthTries 3' \
    'LoginGraceTime 30'
} > "$CONFIG"
chmod 600 "$CONFIG"
configure_socket_ports "${OLD_PORTS[@]}" "$NEW_PORT"

if ! sshd -t; then
  restore_config
  rm -f "$STATE_FILE"
  die 'New configuration did not validate; original settings restored.'
fi
# Ensure a Match block or an earlier Include does not override the intended policy.
for IP in 127.0.0.1 198.51.100.9; do
  ROOT_POLICY=$(sshd -T -C "user=root,addr=$IP,host=$IP" | awk '$1 == "permitrootlogin" {print $2}')
  [[ "$ROOT_POLICY" == no ]] || { restore_config; rm -f "$STATE_FILE"; die "Root still permitted from $IP; conflicting Match/Include settings."; }
done
USER_POLICY=$(sshd -T -C "user=$USERNAME,addr=198.51.100.9,host=198.51.100.9")
USER_PASSWORD_POLICY=$(printf '%s\n' "$USER_POLICY" | awk '$1 == "passwordauthentication" {print $2}')
USER_KEY_POLICY=$(printf '%s\n' "$USER_POLICY" | awk '$1 == "pubkeyauthentication" {print $2}')
[[ "$USER_PASSWORD_POLICY" == no && "$USER_KEY_POLICY" == yes ]] || { restore_config; rm -f "$STATE_FILE"; die 'SSH auth settings are overridden by existing config.'; }

# Set up automatic rollback BEFORE restarting the SSH listener.
if ! systemd-run --collect --unit="$ROLLBACK_UNIT" --on-active="$TIMEOUT" \
  --timer-property=AccuracySec=10s "$CONTROL" --rollback >/dev/null; then
  restore_config
  rm -f "$STATE_FILE"
  die 'Unable to arm automatic rollback. SSH settings restored.'
fi

systemctl daemon-reload
if [[ "$SOCKET_ACTIVE" == 1 ]]; then
  if ! systemctl restart ssh.socket; then
    restore_config
    die 'Unable to restart ssh.socket. Restored previous settings.'
  fi
fi
if ! systemctl reload ssh.service 2>/dev/null; then
  systemctl try-restart ssh.service >/dev/null 2>&1 || true
fi
if ! ss -Hlt "( sport = :$NEW_PORT )" | grep -q .; then
  restore_config
  die "New SSH port $NEW_PORT is not listening. Original configuration restored."
fi

say 'Temporary SSH hardening configured.'
printf 'New user: %s\n' "$USERNAME"
printf 'New SSH port: %s\n' "$NEW_PORT"
printf 'Old SSH port(s) temporarily left open: %s\n' "${OLD_PORTS[*]}"
printf 'Root SSH login: disabled\nPassword SSH login: disabled\nPublic key login: enabled\n'
warn 'If your VPS provider has an external firewall, manually allow the NEW TCP port before testing.'
printf '\n1) KEEP THIS CURRENT SSH SESSION OPEN.\n'
printf '2) From a SECOND terminal, log in with YOUR PRIVATE key (not the public key):\n'
printf '   ssh -p %s -i /path/to/private_key %s@SERVER_IP\n' "$NEW_PORT" "$USERNAME"
printf '3) From that NEW SSH SESSION, run EXACTLY:\n'
printf '   sudo env SYNET_CONNECTED_PORT="${SSH_CONNECTION##* }" %s --confirm\n' "$CONTROL"
printf '\nIf you do not confirm within 15 minutes, the ORIGINAL SSH CONFIG is restored automatically.\n'
printf 'No reboot required.\n'