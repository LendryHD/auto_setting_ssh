# Synet SSH Hardening

A cautious interactive Ubuntu SSH hardening helper (Ubuntu 22.04 / 24.04 / 26.04).

**Warning:** This changes SSH authentication and the listening port. Have a working VPS provider console and a private key matching the public key you supply. Test on a non-production VM before production use.

## Install from GitHub

Download and run the published script after reviewing its source:

```bash
curl -fsSL https://raw.githubusercontent.com/LendryHD/auto_setting_ssh/main/synet-ssh-hardening.sh -o /tmp/synet-ssh-hardening.sh && sudo bash /tmp/synet-ssh-hardening.sh
```

It prompts for a Linux username, a password used for sudo (not for SSH login), and a **single public** SSH authorized key line (`ssh-ed25519 AAAA...`). Never provide your private key or paste secrets into a public repository.

The tool creates or updates the specified Linux user, adds the user to the sudo group, writes the public key to `~/.ssh/authorized_keys`, disables SSH password and root logins, and selects a random high-numbered SSH port. If UFW is active, the new port is allowed there. It handles systemd `ssh.socket` listeners.

## Confirmation is essential

Leave your old SSH session open. The tool keeps the old port temporarily while the new one is tested. Open **another** terminal with the new SSH port and supplied key. From the new SSH session, run:

```bash
sudo env SYNET_CONNECTED_PORT="${SSH_CONNECTION##* }" /usr/local/sbin/synet-ssh-guard --confirm
```

After confirmation, old SSH listeners are closed by this tool. If confirmation is not received within 15 minutes, a systemd timer attempts to restore the previous SSH configuration. The script does **not** reverse new user/password/authorized_keys changes. If the rollback timer, systemd, or VPS network is not functional, use your VPS provider's out-of-band console.

External cloud-provider firewalls are **not** managed; permit the new SSH TCP port there before testing. Check old UFW allow rules after confirmation; the tool intentionally leaves them alone because they might be shared.

## Security notes

* Review the file and ideally pin to a tested commit SHA instead of using a moving `main` branch in production.
* The script has passed `bash -n` syntax validation, **not** end-to-end testing on a live VPS.
* Changing the port alone does not prevent attacks. Keys, root/password SSH restrictions, and firewall policies matter more.
* SSH jump hosts, automation (such as eGames), and SSH clients need to be updated for the new port/account policy.