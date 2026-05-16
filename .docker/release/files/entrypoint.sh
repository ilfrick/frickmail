#!/bin/sh
set -eu

DEBUG=${DEBUG:-}
if [ "$DEBUG" = 'true' ]; then
    set -x
fi
UPLOAD_MAX_SIZE=${UPLOAD_MAX_SIZE:-25M}
MEMORY_LIMIT=${MEMORY_LIMIT:-128M}
SECURE_COOKIES=${SECURE_COOKIES:-true}

# Set attachment size limit
sed -i "s/<UPLOAD_MAX_SIZE>/$UPLOAD_MAX_SIZE/g" /usr/local/etc/php-fpm.d/php-fpm.conf /etc/nginx/nginx.conf
sed -i "s/<MEMORY_LIMIT>/$MEMORY_LIMIT/g" /usr/local/etc/php-fpm.d/php-fpm.conf

# Secure cookies
if [ "${SECURE_COOKIES}" = 'true' ]; then
    echo "[INFO] Secure cookies activated"
        {
        	echo 'session.cookie_httponly = On';
        	echo 'session.cookie_secure = On';
        	echo 'session.use_only_cookies = On';
        } > /usr/local/etc/php/conf.d/cookies.ini;
fi

echo "[INFO] Snappymail version: $( ls /snappymail/snappymail/v )"

# Set permissions on snappymail data
echo "[INFO] Setting permissions on /var/lib/snappymail"
chown -R www-data:www-data /var/lib/snappymail/
chmod 550 /var/lib/snappymail/
find /var/lib/snappymail/ -type d -exec chmod 750 {} \;

# Create snappymail default config if absent
SNAPPYMAIL_CONFIG_FILE=/var/lib/snappymail/_data_/_default_/configs/application.ini
if [ ! -f "$SNAPPYMAIL_CONFIG_FILE" ]; then
    echo "[INFO] Creating default Snappymail configuration: $SNAPPYMAIL_CONFIG_FILE"
    # Run snappymail and exit. This populates the snappymail data directory and generates the config file
    # On error, print php exception and exit
    EXITCODE=
    su - www-data -s /bin/sh -c 'php /snappymail/index.php' > /tmp/out || EXITCODE=$?
    if [ -n "$EXITCODE" ]; then
        cat /tmp/out
        exit "$EXITCODE"
    fi
fi

# Frickmail: sync bundled plugins on every boot. These are image-managed
# (not user-installed) so we always overwrite to pick up upgrades.
SNAPPYMAIL_PLUGINS_DIR=/var/lib/snappymail/_data_/_default_/plugins
if [ -d /snappymail/plugins-bundled ] && [ -d /var/lib/snappymail/_data_/_default_ ]; then
    mkdir -p "$SNAPPYMAIL_PLUGINS_DIR"
    for plugin in login-oauth2 login-gmail login-o365 contacts-sync calendar frickmail-user frickmail-theme; do
        if [ -d "/snappymail/plugins-bundled/$plugin" ]; then
            echo "[INFO] Syncing Frickmail plugin: $plugin"
            rm -rf "$SNAPPYMAIL_PLUGINS_DIR/$plugin"
            cp -r "/snappymail/plugins-bundled/$plugin" "$SNAPPYMAIL_PLUGINS_DIR/$plugin"
        fi
    done
    chown -R www-data:www-data "$SNAPPYMAIL_PLUGINS_DIR"
    # Bust SnappyMail's plugin-JS cache so new bundled JS is served immediately
    rm -rf /var/lib/snappymail/_data_/_default_/cache/* 2>/dev/null || true
    # Enable plugins in application.ini if currently disabled / unset
    if grep -q '^enable = Off' "$SNAPPYMAIL_CONFIG_FILE" 2>/dev/null; then
        sed -i '/^\[plugins\]/,/^\[/{s/^enable = Off/enable = On/}' "$SNAPPYMAIL_CONFIG_FILE"
    fi
    # Always ensure the full plugin list is set (idempotent)
    sed -i 's|^enabled_list = .*|enabled_list = "login-oauth2,login-gmail,login-o365,contacts-sync,calendar,frickmail-user,frickmail-theme"|' "$SNAPPYMAIL_CONFIG_FILE"
fi

# Frickmail: provision Postgres schema for users + mail accounts (idempotent)
FRICKMAIL_DB_HOST="${FRICKMAIL_DB_HOST:-db}"
FRICKMAIL_DB_PORT="${FRICKMAIL_DB_PORT:-5432}"
FRICKMAIL_DB_NAME="${FRICKMAIL_DB_NAME:-frickmail}"
FRICKMAIL_DB_USER="${FRICKMAIL_DB_USER:-frickmail}"
FRICKMAIL_DB_PASSWORD="${FRICKMAIL_DB_PASSWORD:-frickmail}"
if command -v php >/dev/null 2>&1 && [ -n "${FRICKMAIL_DB_HOST}" ]; then
    echo "[INFO] Provisioning Frickmail user schema on ${FRICKMAIL_DB_HOST}:${FRICKMAIL_DB_PORT}/${FRICKMAIL_DB_NAME}"
    PGPASSWORD="$FRICKMAIL_DB_PASSWORD" \
    FRICKMAIL_DB_HOST="$FRICKMAIL_DB_HOST" FRICKMAIL_DB_PORT="$FRICKMAIL_DB_PORT" \
    FRICKMAIL_DB_NAME="$FRICKMAIL_DB_NAME" FRICKMAIL_DB_USER="$FRICKMAIL_DB_USER" \
    FRICKMAIL_DB_PASSWORD="$FRICKMAIL_DB_PASSWORD" \
    php -r '
        $tries = 30;
        while ($tries-- > 0) {
            try {
                $pdo = new PDO(
                    sprintf("pgsql:host=%s;port=%s;dbname=%s",
                        getenv("FRICKMAIL_DB_HOST"),
                        getenv("FRICKMAIL_DB_PORT"),
                        getenv("FRICKMAIL_DB_NAME")),
                    getenv("FRICKMAIL_DB_USER"),
                    getenv("FRICKMAIL_DB_PASSWORD"),
                    [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 3]
                );
                break;
            } catch (Throwable $e) {
                if ($tries === 0) { fwrite(STDERR, "[ERR] Postgres unreachable: " . $e->getMessage() . PHP_EOL); exit(1); }
                sleep(1);
            }
        }
        $pdo->exec("CREATE TABLE IF NOT EXISTS frickmail_users (
            id BIGSERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT,
            password_hash TEXT NOT NULL,
            kdf_salt BYTEA NOT NULL,
            settings JSONB NOT NULL DEFAULT '\''{}'\''::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )");
        $pdo->exec("CREATE TABLE IF NOT EXISTS frickmail_mail_accounts (
            id BIGSERIAL PRIMARY KEY,
            user_id BIGINT NOT NULL REFERENCES frickmail_users(id) ON DELETE CASCADE,
            label TEXT NOT NULL,
            email TEXT NOT NULL,
            type TEXT NOT NULL CHECK (type IN ('\''imap'\'','\''gmail'\'','\''o365'\'')),
            imap_host TEXT, imap_port INT, imap_secure TEXT,
            smtp_host TEXT, smtp_port INT, smtp_secure TEXT,
            login TEXT,
            encrypted_password BYTEA,
            encrypted_oauth_refresh_token BYTEA,
            oauth_tenant TEXT,
            is_primary BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )");
        $pdo->exec("CREATE INDEX IF NOT EXISTS idx_fm_mail_accounts_user ON frickmail_mail_accounts(user_id)");
        $pdo->exec("CREATE UNIQUE INDEX IF NOT EXISTS uq_fm_mail_accounts_primary ON frickmail_mail_accounts(user_id) WHERE is_primary");
        $pdo->exec("CREATE TABLE IF NOT EXISTS frickmail_password_resets (
            id BIGSERIAL PRIMARY KEY,
            user_id BIGINT NOT NULL REFERENCES frickmail_users(id) ON DELETE CASCADE,
            token_hash TEXT NOT NULL UNIQUE,
            expires_at TIMESTAMPTZ NOT NULL,
            used_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )");
        $pdo->exec("CREATE INDEX IF NOT EXISTS idx_fm_pwreset_user ON frickmail_password_resets(user_id)");
        $pdo->exec("CREATE INDEX IF NOT EXISTS idx_fm_pwreset_expires ON frickmail_password_resets(expires_at)");
        $pdo->exec("ALTER TABLE frickmail_users ADD COLUMN IF NOT EXISTS totp_secret TEXT");
        echo "[OK] Frickmail schema ready" . PHP_EOL;
    ' || echo "[WARN] Frickmail schema migration skipped (DB unreachable)"
fi

echo "[INFO] Overriding values in snappymail configuration: $SNAPPYMAIL_CONFIG_FILE"
# Frickmail: rebrand title/loading_description if still using the upstream defaults
sed -i 's/^title = "SnappyMail Webmail"/title = "Frickmail"/' "$SNAPPYMAIL_CONFIG_FILE"
sed -i 's/^title = "SnappyMail"/title = "Frickmail"/' "$SNAPPYMAIL_CONFIG_FILE"
sed -i 's/^loading_description = "SnappyMail"/loading_description = "Frickmail"/' "$SNAPPYMAIL_CONFIG_FILE"
# Enable output of snappymail logs
sed '/^\; Enable logging/{
N
s/enable = Off/enable = On/
}' -i $SNAPPYMAIL_CONFIG_FILE
# Redirect snappymail logs to stderr /stdout
sed 's/^filename = .*/filename = "stderr"/' -i $SNAPPYMAIL_CONFIG_FILE
sed 's/^write_on_error_only = .*/write_on_error_only = Off/' -i $SNAPPYMAIL_CONFIG_FILE
sed 's/^write_on_php_error_only = .*/write_on_php_error_only = On/' -i $SNAPPYMAIL_CONFIG_FILE
# Always enable snappymail Auth logging
sed 's/^auth_logging = .*/auth_logging = On/' -i $SNAPPYMAIL_CONFIG_FILE
sed 's/^auth_logging_filename = .*/auth_logging_filename = "auth.log"/' -i $SNAPPYMAIL_CONFIG_FILE
sed 's/^auth_logging_format = .*/auth_logging_format = "[{date:Y-m-d H:i:s}] Auth failed: ip={request:ip} user={imap:login} host={imap:host} port={imap:port}"/' -i $SNAPPYMAIL_CONFIG_FILE
sed 's/^auth_syslog = .*/auth_syslog = Off/' -i $SNAPPYMAIL_CONFIG_FILE

(
    while ! nc -vz -w 1 127.0.0.1 8888 > /dev/null 2>&1; do echo "[INFO] Checking whether nginx is alive"; sleep 1; done
    while ! nc -vz -w 1 127.0.0.1 9000 > /dev/null 2>&1; do echo "[INFO] Checking whether php-fpm is alive"; sleep 1; done
    # Create snappymail admin password if absent
    SNAPPYMAIL_ADMIN_PASSWORD_FILE=/var/lib/snappymail/_data_/_default_/admin_password.txt
    if [ ! -f "$SNAPPYMAIL_ADMIN_PASSWORD_FILE" ]; then
        echo "[INFO] Creating Snappymail admin password file: $SNAPPYMAIL_ADMIN_PASSWORD_FILE"
        wget -T 1 -qO- 'http://127.0.0.1:8888/?/AdminAppData/0/12345/' > /dev/null
        echo "[INFO] Snappymail Admin Panel ready at http://localhost:8888/?admin. Login using password in $SNAPPYMAIL_ADMIN_PASSWORD_FILE"
    fi

    wget -T 1 -qO- 'http://127.0.0.1:8888/' > /dev/null
    echo "[INFO] Snappymail ready at http://localhost:8888/"
) &

# RUN !
exec /usr/bin/supervisord -c /supervisor.conf --pidfile /run/supervisord.pid
