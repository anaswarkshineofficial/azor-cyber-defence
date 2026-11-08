# AZOR CYBER DEFENCE — Web-only deployment

This package contains the existing FastAPI dashboard and its SQLite database. It intentionally excludes Kali CLI files, the Telegram bot process, local virtual environments, bytecode caches, and the original `.env` file.

## Ubuntu deployment

1. Upload and extract this folder to `/opt/azor`.
2. Create a service user and persistent database directory:

   ```bash
   sudo useradd --system --home /opt/azor --shell /usr/sbin/nologin azor
   sudo mkdir -p /var/lib/azor /etc/azor
   sudo cp /opt/azor/azor_cases.db /var/lib/azor/azor_cases.db
   sudo chown -R azor:azor /opt/azor /var/lib/azor
   sudo chmod 750 /var/lib/azor
   ```

   If you have already copied a newer database to `/var/lib/azor`, do not overwrite it with the bundled copy.

3. Create `/etc/azor/azor.env` with these settings (replace the password with a long, unique random value):

   ```env
   ADMIN_USERNAME=admin
   ADMIN_PASSWORD=REPLACE_WITH_A_LONG_RANDOM_SECRET
   DATABASE_PATH=/var/lib/azor/azor_cases.db
   ```

   Secure it:

   ```bash
   sudo chown root:azor /etc/azor/azor.env
   sudo chmod 640 /etc/azor/azor.env
   ```

4. Install dependencies and create the virtual environment:

   ```bash
   sudo -u azor python3 -m venv /opt/azor/venv
   sudo -u azor /opt/azor/venv/bin/pip install --upgrade pip
   sudo -u azor /opt/azor/venv/bin/pip install -r /opt/azor/requirements-web.txt
   ```

5. Install and start the service:

   ```bash
   sudo cp /opt/azor/deploy/azor-dashboard.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now azor-dashboard
   sudo systemctl status azor-dashboard
   ```

6. Test locally on the VM:

   ```bash
   curl -I http://127.0.0.1:8000/
   sudo journalctl -u azor-dashboard -f
   ```

## Private internet access

Connect Cloudflare Tunnel to `http://localhost:8000`, then create a Cloudflare Access self-hosted application for the hostname and allow only your team's approved email addresses. Do not expose port 8000 directly to the public internet. Keep SSH restricted to trusted administrator IPs/keys.

## Backups

Back up `/var/lib/azor/azor_cases.db` regularly to encrypted storage. For a consistent SQLite backup, use the SQLite backup API or `sqlite3 /var/lib/azor/azor_cases.db ".backup '/secure-backup/azor_cases.db'"`. Test restoring a backup before relying on it.

## Important

- This app currently uses HTTP Basic authentication. Put it behind HTTPS and Cloudflare Access; use unique credentials and MFA for team members.
- The dashboard's app-level login is one shared admin account, not individual team accounts with role-based permissions. Cloudflare Access controls who can reach it, but does not create separate dashboard identities.
- The original `.env` file and any bot token are not included. Rotate credentials that were present in the uploaded archive before going live.
- This package is the web dashboard only. No Kali Linux CLI or Telegram bot service is deployed.
