#!/bin/bash

# Deploy credenza in a simple standalone fashion useful
# on Red Hat flavored systems, e.g. Rocky, Fedora, RHEL.
#
# 1. Deploy via distro's httpd + mod_wsgi
# 2. Provision credenza daemon account
# 3. Adjust SE-Linux policy for mod_wsgi sandbox
# 4. Setup default configuration files for credenza
#
# Use idempotent, non-clobbering methods so that a clean
# install leads to a (nearly) usable state, but any local
# customization is preserved.
#
# Default config: (may change)
#
# - syslog logging
# - sqlite backend
# - Globus Auth identity provider
# - Globus Groups group augmentation
#

########
# some helper funcs

TMP_ENV=$(mktemp /tmp/credenza.env.XXXXXX)
TMP_OIDC=$(mktemp /tmp/oidc_idp_profiles.json.XXXXX)
TMP_KEY=$(mktemp /tmp/encryption_key.json.XXXXXX)

cleanup()
{
    rm -f "${TMP_ENV}" "${TMP_OIDC}" "${TMP_KEY}"
}

trap cleanup 0

error()
{
    echo "$@" >&2
    exit 1
}

idempotent_semanage_add()
{
    # args: "type" "filepattern"
    semanage fcontext --add --type "$1" "$2" \
        || semanage fcontext --modify --type "$1" "$2" \
        || error Failed to install SE-Linux context "$1" for "$2"
}
########

# sanity check runtime requirements
[[ $(id -u) -eq 0 ]] || error This script must run as root

[[ -r /etc/redhat-release ]] || error Failed to find /etc/redhat-release

detect_psycopg2()
{
    found=$(rpm -q -a | grep '^python3[.0-9]*-psycopg2')
    [[ -n "$found" ]] || error Please install an appropriate python3*-psycopg2 RPM for this distro and your chosen Python 3 runtime
    echo "found $found"
}

detect_mod_wsgi()
{
    found=$(rpm -q -a | grep '^python3[.0-9]*-mod_wsgi')
    [[ -n "$found" ]] || error Please install an appropriate python3*-mod_wsgi RPM for this distro and your chosen Python 3 runtime
    echo "found $found"
}

# whitelist systems we think ought to work with this script
case "$(cat /etc/redhat-release)" in
    Red\ Hat\ Enterprise\ Linux\ release\ 9*)
	detect_psycopg2
	detect_mod_wsgi
        ;;
    Rocky\ Linux\ release\ 8*)
	detect_psycopg2
	detect_mod_wsgi
        ;;
    Fedora\ release\ 4*)
	detect_mod_wsgi
        ;;
    *)
        error Failed to detect a tested Red Hat OS variant
        ;;
esac

# Advisory only: nothing below needs HTTPS to be serving, and a failure here could be DNS,
# httpd or the certificate. Note $(hostname) is not necessarily CREDENZA_BASE_URL.
curl -s "https://$(hostname)/" > /dev/null \
    || echo "WARNING: could not reach https://$(hostname)/ -- verify DNS, httpd and TLS before using this deployment"

[[ -f /etc/httpd/conf.d/wsgi.conf || -f /etc/httpd/conf.modules.d/10-wsgi-python3.conf ]] \
    || error Failed to detect mod_wsgi config prerequisite \(checked /etc/httpd/conf.d/wsgi.conf and /etc/httpd/conf.modules.d/10-wsgi-python3.conf\)

# TODO: change if we can use installed data resources instead of source tree
[[ -f pyproject.toml ]] \
    && grep -q 'name = "credenza"' pyproject.toml \
        || error The current working dir must contain the credenza source tree

# idempotently provision the daemon account and homedir
id credenza \
    || useradd -m -g apache -r credenza \
    || error Failed to create credenza daemon account

[[ -d /home/credenza ]] \
    || error Failed to detect credenza daemon home directory

mkdir -p /home/credenza/config \
    && chown credenza:apache /home/credenza/config \
    && chmod o= /home/credenza/config \
	|| error Failed to provision /home/credenza/config sub-dir

mkdir -p /home/credenza/secrets \
    && chown credenza:apache /home/credenza/secrets \
    && chmod o= /home/credenza/secrets \
	|| error Failed to provision /home/credenza/secrets sub-dir

pgusercnt=$(su -c "psql -q -t -A -c \"SELECT count(*) FROM pg_roles WHERE rolname = 'credenza'\"" - postgres)
if [[ $? -ne 0 ]]
then
    error Failed to test for presence of credenza postgresql role
fi

[[ $pgusercnt -eq 1 ]] \
    || su -c "createuser -d -R -S credenza" - postgres \
    || error Failed to create credenza postgresql role

pgdbcnt=$(su -c "psql -q -t -A -c \"SELECT count(*) FROM pg_database WHERE datname = 'credenza'\"" - postgres)
if [[ $? -ne 0 ]]
then
    error Failed to test for presence of credenza postgresql DB
fi

if [[ $pgdbcnt -eq 1 ]]
then
    CREDENZA_DB_CREATED=false
else
    su -c "createdb -O credenza credenza" - postgres || error Failed to create credenza postgresql DB
    CREDENZA_DB_CREATED=true
fi

# idempotently deploy default configs
[[ -f /etc/httpd/conf.d/wsgi_credenza.conf ]] \
    || install -o root -m u=rw,og=r config/wsgi_credenza.conf /etc/httpd/conf.d/ \
    || error Failed to deploy wsgi_credenza.conf

# TODO: change 
cat > "${TMP_ENV}" <<EOF
CREDENZA_DEFAULT_REALM=globus
CREDENZA_ENABLE_LEGACY_API=true
CREDENZA_AUDIT_USE_SYSLOG=true
CREDENZA_APP_USE_SYSLOG=true
CREDENZA_ENABLE_REFRESH_WORKER=true
CREDENZA_STORAGE_BACKEND=postgresql
CREDENZA_STORAGE_BACKEND_URL=postgresql:///credenza
CREDENZA_BASE_URL="https://$(hostname)/authn"
CREDENZA_POST_LOGIN_REDIRECT=/authn/session
CREDENZA_POST_LOGOUT_REDIRECT_URL="https://$(hostname)/"
EOF
[[ $? = 0 ]] || error Failed to create ${TMP_ENV}

[[ -f /home/credenza/config/credenza.env ]] \
    || install -o root -g apache -m u=rw,og=r -T "${TMP_ENV}" /home/credenza/config/credenza.env \
    || error Failed to deploy /home/credenza/config/credenza.env

sed -e "s/localhost/$(hostname)/" \
    < ./config/oidc_idp_profiles.sample.json \
    > "${TMP_OIDC}" \
    || error Failed to create ${TMP_OIDC}

[[ -f /home/credenza/config/oidc_idp_profiles.json ]] \
    || install -o root -g apache -m u=rw,og=r -T "${TMP_OIDC}" /home/credenza/config/oidc_idp_profiles.json \
    || error Failed to deploy /home/credenza/config/oidc_idp_profiles.json

# set minimal permissions for SE-Linux sandboxed WSGI daemon
idempotent_semanage_add \
    httpd_sys_content_t \
    '/home/credenza/config/.*'

idempotent_semanage_add \
    httpd_sys_content_t \
    '/home/credenza/secrets/.*'

# Session encryption key. Generate one only when this run also created the database, the one
# state in which no encrypted session data can exist yet. If the database was already present,
# a missing key file may mean the key was lost rather than never set, and generating a new one
# would silently destroy every stored session, so warn and let credenza fail closed at startup
# instead. An existing key file is never touched. This runs before restorecon so that a newly
# generated key gets the SE-Linux label registered above.
CREDENZA_ENV=/home/credenza/config/credenza.env
CREDENZA_KEYFILE=/home/credenza/secrets/encryption_key.json

# a '$' in the value means an unsubstituted "${CREDENZA_ENCRYPTION_KEY}" template, which
# interpolates to the empty string at runtime and is not a usable key
CREDENZA_KEY_CONFIGURED=false
if [[ -n "$CREDENZA_ENCRYPTION_KEY" ]]
then
    CREDENZA_KEY_CONFIGURED=true
elif grep -Eq '^CREDENZA_ENCRYPTION_KEY=.' "$CREDENZA_ENV" && ! grep -Eq '^CREDENZA_ENCRYPTION_KEY=.*[$]' "$CREDENZA_ENV"
then
    CREDENZA_KEY_CONFIGURED=true
fi

if grep -Eq '^CREDENZA_ENCRYPT_SESSION_DATA=true' "$CREDENZA_ENV" && [[ $CREDENZA_KEY_CONFIGURED = false ]]
then
    if [[ -r "$CREDENZA_KEYFILE" ]]
    then
        echo "Using existing session encryption key ${CREDENZA_KEYFILE}"
    elif [[ $CREDENZA_DB_CREATED = true ]]
    then
        python3 -c 'import json, secrets; print(json.dumps({"encryption_key": secrets.token_urlsafe(24)}, indent=2))' > "${TMP_KEY}" \
            || error Failed to generate a session encryption key
        install -o credenza -g apache -m u=rw,go= -T "${TMP_KEY}" "${CREDENZA_KEYFILE}" \
            || error Failed to deploy "${CREDENZA_KEYFILE}"
        echo "Generated session encryption key ${CREDENZA_KEYFILE} -- back this up, losing it invalidates every stored session"
    else
        echo WARNING: session encryption is enabled but "${CREDENZA_KEYFILE}" must be populated by the admin
    fi
fi

restorecon -rv /home/credenza/

# Each realm in oidc_idp_profiles.json names a client_secret_file that is provisioned out
# of band. The filenames vary by provider, so just check whether anything was provisioned
# at all. encryption_key.json is excluded: this script may have generated it above.
if [[ -z "$(find /home/credenza/secrets -maxdepth 1 -name '*.json' ! -name 'encryption_key.json' -print -quit 2>/dev/null)" ]]
then
    echo WARNING: no OIDC client secret files in /home/credenza/secrets -- the client_secret_file for each configured realm must be populated by the admin
fi
