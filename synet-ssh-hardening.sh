#!/usr/bin/env bash
# Synet SSH Hardening v1.3 — защита SSH на Ubuntu 22.04/24.04/26.04.
# Использование: sudo bash synet-ssh-hardening.sh
# После входа в новую SSH-сессию под новым пользователем на порту 22:
#   sudo env SYNET_CONNECTED_PORT="${SSH_CONNECTION##* }" /usr/local/sbin/synet-ssh-guard --confirm
# Без подтверждения прежние настройки восстанавливаются через 15 минут.
set -Eeuo pipefail
umask 077

CONTROL=/usr/local/sbin/synet-ssh-guard
STATE_DIR=/var/lib/synet-ssh-guard
STATE_FILE=$STATE_DIR/state
CONFIG=/etc/ssh/sshd_config.d/00-synet-ssh-hardening.conf
ROLLBACK_UNIT=synet-ssh-guard-rollback
TIMEOUT=15min
OWN_PENDING=0
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
  [[ "${SYNET_CONNECTED_PORT:-}" == 22 && "${SUDO_USER:-}" == "$TARGET_USERNAME" ]] || die \
    'Подтвердите только из НОВОГО SSH-подключения под указанным пользователем на порту 22.'
  sshd -t || die 'Конфигурация SSH содержит ошибки. Подтверждение отменено.'
  ss -Hlt '( sport = :22 )' | grep -q . || die 'SSH больше не слушает порт 22. Подтверждение отменено.'
  systemctl stop "${ROLLBACK_UNIT}.timer" 2>/dev/null || true
  rm -f "$STATE_FILE"
  say 'Новый вход по SSH-ключу подтверждён. Защита активна, порт SSH остался 22.'
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
printf 'SSH-порт останется 22. После настройки нужно проверить новый вход, иначе сработает откат.\n'
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
# Скрипт никогда не меняет SSH-порт и не трогает ssh.socket.
NEW_PORT=22
if ! ss -Hlt '( sport = :22 )' | grep -q .; then
  die 'SSH не слушает порт 22. Из соображений безопасности скрипт не меняет текущий порт автоматически.'
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
# Record safe root-written values for eventual rollback. No password or key is saved here.
{
  printf 'HAD_CONFIG=%q\n' "$HAD_CONFIG"
  printf 'TARGET_USERNAME=%q\n' "$USERNAME"
} > "$STATE_FILE"
chmod 600 "$STATE_FILE"
OWN_PENDING=1

# Install control command for confirmation/automatic rollback.
# Run the installer from a real downloaded file (not `curl | bash`).
[[ -f "$0" && -r "$0" ]] || die 'Запускайте скачанный файл, а не команду через конвейер curl | bash.'
install -m 700 -- "$(readlink -f "$0")" "$CONTROL"

# Изменяем только правила авторизации SSH. Порт и ssh.socket остаются без изменений.
{
  printf '# Synet SSH Hardening: только правила входа, порт 22 не меняется.\n'
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

if ! systemctl reload ssh.service 2>/dev/null; then
  restore_config
  die 'Не удалось применить настройки SSH. Прежние настройки восстановлены.'
fi
if ! ss -Hlt '( sport = :22 )' | grep -q .; then
  restore_config
  die 'Порт 22 перестал прослушиваться. Прежняя конфигурация восстановлена.'
fi

say 'Временная защищённая конфигурация SSH создана.'
printf 'Пользователь: %s\n' "$USERNAME"
printf 'Порт SSH: 22 (не изменён)\n'
printf 'Вход root: запрещён\nВход по SSH-паролю: запрещён\nВход по публичному ключу: включён\n'
printf '\n1) НЕ ЗАКРЫВАЙТЕ текущую SSH-сессию.\n'
printf '2) Откройте ВТОРОЙ терминал и войдите под настроенным пользователем со своим ПРИВАТНЫМ ключом:\n'
printf '   ssh -p 22 -i /путь/к/приватному_ключу %s@IP_СЕРВЕРА\n' "$USERNAME"
printf '3) После успешного входа выполните в НОВОЙ SSH-сессии:\n'
printf '   sudo env SYNET_CONNECTED_PORT="${SSH_CONNECTION##* }" %s --confirm\n' "$CONTROL"
printf '\nЕсли за 15 минут не подтвердить вход, прежние настройки SSH восстановятся автоматически.\n'
printf 'Перезагрузка не нужна.\n'