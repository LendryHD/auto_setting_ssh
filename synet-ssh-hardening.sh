#!/usr/bin/env bash
# Synet SSH Hardening v1.2 — защита SSH на Ubuntu 22.04/24.04/26.04.
# Использование: sudo bash synet-ssh-hardening.sh
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
OWN_PENDING=0
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
warn() { printf '\n\033[1;33mПРЕДУПРЕЖДЕНИЕ: %s\033[0m\n' "$*" >&2; }
die()  { printf '\nОШИБКА: %s\n' "$*" >&2; exit 1; }
require_root() { [[ ${EUID} -eq 0 ]] || die 'Запустите скрипт с правами root через sudo.'; }

load_state() {
  [[ -f "$STATE_FILE" ]] || die 'Нет настройки SSH, ожидающей подтверждения.'
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
    printf 'Нет настроек, ожидающих отката.\n'
    exit 0
  fi
  warn 'Подтверждение не получено — восстанавливаем прежние настройки SSH.'
  restore_config
  rm -f "$STATE_FILE"
  printf 'Прежние настройки SSH восстановлены. Пользователь и публичный ключ сохранены.\n'
}

finish() {
  require_root
  load_state
  [[ "${SYNET_CONNECTED_PORT:-}" == "$NEW_PORT" ]] || die \
    "Подтвердите вход только из НОВОЙ SSH-сессии через порт $NEW_PORT, using: sudo env SYNET_CONNECTED_PORT=\"\${SSH_CONNECTION##* }\" $CONTROL --confirm"
  say "Новая SSH-сессия подтверждена на порту $NEW_PORT. Закрываем старые SSH-порты."
  # Keep only the designated SSH port in our snippet. The original sshd_config is untouched.
  sed -i -E '/^Port [0-9]+$/d' "$CONFIG"
  { printf 'Port %s\n' "$NEW_PORT"; cat "$CONFIG"; } > "$STATE_DIR/finished-config"
  install -m 600 "$STATE_DIR/finished-config" "$CONFIG"
  sshd -t || { restore_config; die 'Ошибка конфигурации SSH: прежние настройки восстановлены.'; }
  configure_socket_ports "$NEW_PORT"
  systemctl daemon-reload
  if [[ "$SOCKET_ACTIVE" == 1 ]]; then systemctl restart ssh.socket; fi
  systemctl reload ssh.service 2>/dev/null || true
  if ! ss -Hlt "( sport = :$NEW_PORT )" | grep -q .; then
    restore_config
    die "New port $NEW_PORT не прослушивается: прежние настройки восстановлены."
  fi
  read -r -a PREVIOUS_PORTS <<< "$OLD_PORTS_JOINED"
  for port in "${PREVIOUS_PORTS[@]}"; do
    [[ "$port" == "$NEW_PORT" ]] && continue
    if ss -Hlt "( sport = :$port )" | grep -q .; then
      restore_config
      die "Old port $port всё ещё прослушивается (возможно, конфликт с Port/ListenStream); прежние настройки восстановлены."
    fi
  done
  systemctl stop "${ROLLBACK_UNIT}.timer" 2>/dev/null || true
  # Old firewall allow rules are intentionally left in place: deleting shared rules may break other services.
  rm -f "$STATE_FILE"
  say "Защита SSH включена. Порт: $NEW_PORT. Вход root и вход по паролю отключены."
  warn 'Старые разрешающие правила файрвола могут остаться. Проверьте UFW и файрвол провайдера, а также отсутствие SSH на старом порту.'
}

if [[ ${1:-} == '--rollback' ]]; then rollback; exit 0; fi
if [[ ${1:-} == '--confirm' ]]; then finish; exit 0; fi
[[ $# == 0 ]] || die 'Использование: sudo bash synet-ssh-hardening.sh [--confirm|--rollback]'
require_root

# If an error occurs after the state file has been created, restore the
# previous SSH settings instead of leaving an unconfirmed configuration.
cleanup_on_exit() {
  local rc=$?
  [[ -n "${TMP_KEY:-}" ]] && rm -f -- "$TMP_KEY"
  if (( rc != 0 )) && [[ "$OWN_PENDING" == 1 ]] && [[ -f "$STATE_FILE" ]]; then
    warn 'Сбой настройки — восстанавливаем SSH.'
    restore_config || warn 'Автоматический откат не удался. Используйте консоль VPS у провайдера.'
    systemctl stop "${ROLLBACK_UNIT}.timer" 2>/dev/null || true
    rm -f "$STATE_FILE"
  fi
}
trap cleanup_on_exit EXIT

command -v sshd >/dev/null 2>&1 || die 'Сервер OpenSSH не установлен.'
command -v systemctl >/dev/null 2>&1 || die 'Требуется systemd.'
command -v ssh-keygen >/dev/null 2>&1 || die 'Не найдена команда ssh-keygen.'
command -v ss >/dev/null 2>&1 || die 'Не найдена утилита ss (пакет iproute2).'
command -v systemd-run >/dev/null 2>&1 || die 'Для автоматического отката требуется systemd-run.'
[[ -f /etc/ssh/sshd_config ]] || die 'Не найден файл /etc/ssh/sshd_config.'
[[ ! -f "$STATE_FILE" ]] || die "Предыдущая настройка SSH ещё ждёт подтверждения. Подтвердите её или дождитесь отката."

say 'Synet — автоматическая защита SSH'
printf 'Скрипт запросит имя пользователя, пароль для sudo и ОДИН публичный SSH-ключ.\n'
printf 'Новый SSH-порт будет выбран автоматически. Старые порты временно сохраняются для отката.\n'
read -r -p 'Имя пользователя (например, lendry): ' USERNAME
[[ "$USERNAME" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die 'Недопустимое имя: только строчные латинские буквы, цифры, _ и -.'
[[ "$USERNAME" != root ]] || die 'Нельзя использовать root.'
read -r -s -p 'Пароль пользователя для sudo (вход в SSH по паролю отключится): ' PASSWORD
printf '\n'
[[ -n "$PASSWORD" && ${#PASSWORD} -ge 8 ]] || die 'Пароль должен быть не короче 8 символов.'
read -r -p 'Вставьте ПУБЛИЧНЫЙ SSH-ключ одной строкой (ssh-ed25519 AAAA...): ' PUBLIC_KEY
[[ "$PUBLIC_KEY" == ssh-* || "$PUBLIC_KEY" == ecdsa-* || "$PUBLIC_KEY" == sk-* ]] || die 'Ожидается публичный ключ, начинающийся с ssh-ed25519, ssh-rsa, ecdsa-... и т. д.'
[[ "$PUBLIC_KEY" != *$'\r'* && "$PUBLIC_KEY" != *$'\n'* ]] || die 'Ключ должен быть одной строкой.'

TMP_KEY=$(mktemp)
printf '%s\n' "$PUBLIC_KEY" > "$TMP_KEY"
ssh-keygen -lf "$TMP_KEY" >/dev/null 2>&1 || die 'Некорректный публичный SSH-ключ.'

# Safety checks before changing SSH configuration.
sshd -t || die 'Текущая конфигурация sshd содержит ошибки. Изменения отменены.'
if systemctl is-active --quiet ssh.socket; then
  SOCKET_ACTIVE=1
else
  SOCKET_ACTIVE=0
fi
if [[ "$SOCKET_ACTIVE" == 1 ]] && grep -qsHE '^[[:space:]]*ListenStream[[:space:]]*=' \
    /etc/systemd/system/ssh.socket.d/*.conf 2>/dev/null; then
  die 'В ssh.socket есть пользовательский ListenStream. Автоматическая смена порта отменена.'
fi

# Collect effective ports. Current sshd_config is otherwise not edited.
mapfile -t OLD_PORTS < <(sshd -T | awk '$1 == "port" {print $2}' | sort -nu)
((${#OLD_PORTS[@]})) || OLD_PORTS=(22)
# Include port 22 as an explicit emergency fallback only if it already listens.
# Random high port must not be in use.
NEW_PORT=${SYNET_SSH_PORT:-}
if [[ -n "$NEW_PORT" ]]; then
  [[ "$NEW_PORT" =~ ^[0-9]{4,5}$ ]] && (( NEW_PORT >= 1024 && NEW_PORT <= 65535 )) || die 'Недопустимое значение SYNET_SSH_PORT.'
  ss -Hlt "( sport = :$NEW_PORT )" | grep -q . && die "Port $NEW_PORT уже занят."
else
  for _ in {1..30}; do
    NEW_PORT=$(shuf -i 20000-49999 -n 1)
    if ! ss -Hlt "( sport = :$NEW_PORT )" | grep -q .; then break; fi
  done
  ss -Hlt "( sport = :$NEW_PORT )" | grep -q . && die 'Не удалось найти свободный порт.'
fi

if ! id "$USERNAME" &>/dev/null; then
  say "Создаём пользователя: $USERNAME"
  useradd -m -s /bin/bash "$USERNAME"
else
  say "Пользователь уже существует: $USERNAME (обновляем пароль, добавляем ключ)"
fi
printf '%s:%s\n' "$USERNAME" "$PASSWORD" | chpasswd
unset PASSWORD
usermod -aG sudo "$USERNAME"
HOME_DIR=$(getent passwd "$USERNAME" | cut -d: -f6)
GROUP=$(id -gn "$USERNAME")
[[ -d "$HOME_DIR" && "$HOME_DIR" != / ]] || die 'Домашняя папка пользователя отсутствует или небезопасна.'
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
OWN_PENDING=1

# Install control command for confirmation/automatic rollback.
# Run the installer from a real downloaded file (not `curl | bash`).
[[ -f "$0" && -r "$0" ]] || die 'Запускайте скачанный файл, а не команду через конвейер curl | bash.'
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
  die 'Новая конфигурация не прошла проверку. Прежние настройки восстановлены.'
fi
# Ensure a Match block or an earlier Include does not override the intended policy.
for IP in 127.0.0.1 198.51.100.9; do
  ROOT_POLICY=$(sshd -T -C "user=root,addr=$IP,host=$IP" | awk '$1 == "permitrootlogin" {print $2}')
  [[ "$ROOT_POLICY" == no ]] || { restore_config; rm -f "$STATE_FILE"; die "Вход root по-прежнему разрешён с $IP; конфликт правил Match/Include."; }
done
USER_POLICY=$(sshd -T -C "user=$USERNAME,addr=198.51.100.9,host=198.51.100.9")
USER_PASSWORD_POLICY=$(printf '%s\n' "$USER_POLICY" | awk '$1 == "passwordauthentication" {print $2}')
USER_KEY_POLICY=$(printf '%s\n' "$USER_POLICY" | awk '$1 == "pubkeyauthentication" {print $2}')
[[ "$USER_PASSWORD_POLICY" == no && "$USER_KEY_POLICY" == yes ]] || { restore_config; rm -f "$STATE_FILE"; die 'Существующие настройки переопределяют параметры SSH-аутентификации.'; }

# Set up automatic rollback BEFORE restarting the SSH listener.
if ! systemd-run --collect --unit="$ROLLBACK_UNIT" --on-active="$TIMEOUT" \
  --timer-property=AccuracySec=10s "$CONTROL" --rollback >/dev/null; then
  restore_config
  rm -f "$STATE_FILE"
  die 'Не удалось запланировать откат. Настройки SSH восстановлены.'
fi

systemctl daemon-reload
if [[ "$SOCKET_ACTIVE" == 1 ]]; then
  if ! systemctl restart ssh.socket; then
    restore_config
    die 'Не удалось перезапустить ssh.socket. Прежние настройки восстановлены.'
  fi
fi
if ! systemctl reload ssh.service 2>/dev/null; then
  systemctl try-restart ssh.service >/dev/null 2>&1 || true
fi
if ! ss -Hlt "( sport = :$NEW_PORT )" | grep -q .; then
  restore_config
  die "Новый SSH-порт $NEW_PORT не прослушивается. Прежняя конфигурация восстановлена."
fi

say 'Временная защищённая конфигурация SSH создана.'
printf 'Новый пользователь: %s\n' "$USERNAME"
printf 'Новый SSH-порт: %s\n' "$NEW_PORT"
printf 'Старые SSH-порты временно оставлены открытыми: %s\n' "${OLD_PORTS[*]}"
printf 'Вход root: запрещён\nВход по SSH-паролю: запрещён\nВход по публичному ключу: включён\n'
warn 'Если у VPS-провайдера есть внешний файрвол, откройте в нём НОВЫЙ TCP-порт до проверки.'
printf '\n1) НЕ ЗАКРЫВАЙТЕ текущую SSH-сессию.\n'
printf '2) Откройте ВТОРОЙ терминал и войдите со СВОИМ ПРИВАТНЫМ ключом (не публичным):\n'
printf '   ssh -p %s -i /путь/к/приватному_ключу %s@IP_СЕРВЕРА\n' "$NEW_PORT" "$USERNAME"
printf '3) В НОВОЙ SSH-сессии выполните СТРОГО эту команду:\n'
printf '   sudo env SYNET_CONNECTED_PORT="${SSH_CONNECTION##* }" %s --confirm\n' "$CONTROL"
printf '\nЕсли за 15 минут не подтвердить вход, прежние настройки SSH восстановятся автоматически.\n'
printf 'Перезагрузка не нужна.\n'