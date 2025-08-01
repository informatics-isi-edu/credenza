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

cleanup()
{
    rm -f "${TMP_ENV}" "${TMP_OIDC}"
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

# whitelist systems we think ought to work with this script
case "$(cat /etc/redhat-release)" in
    Rocky\ Linux\ release\ 8*)
        :
        ;;
    Fedora\ release\ 4*)
        :
        ;;
    *)
        error Failed to detect a tested Red Hat OS variant
        ;;
esac

curl -s "https://$(hostname)/" > /dev/null \
    || error Failed to validate connectivity to "https://$(hostname)/"

[[ -f /etc/httpd/conf.d/wsgi.conf ]] \
    || error Failed to detect /etc/httpd/conf.d/wsgi.conf prerequisite

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

mkdir -p /home/credenza/state \
    && chown credenza:apache /home/credenza/state \
    && chmod o= /home/credenza/state \
	|| error Failed to provision /home/credenza/state sub-dir


# idempotently deploy default configs
[[ -f /etc/httpd/conf.d/wsgi_credenza.conf ]] \
    || install -o root -m u=rw,og=r config/wsgi_credenza.conf /etc/httpd/conf.d/ \
    || error Failed to deploy wsgi_credenza.conf

# TODO: change 
cat > "${TMP_ENV}" <<EOF
CREDENZA_DEFAULT_REALM=globus
CREDENZA_ENABLE_LEGACY_API=true
CREDENZA_ENABLE_REFRESH_WORKER=true
CREDENZA_AUDIT_USE_SYSLOG=true
CREDENZA_STORAGE_BACKEND=sqlite
CREDENZA_STORAGE_BACKEND_URL=/home/credenza/state/credenza-sqlite.db
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

idempotent_semanage_add \
    httpd_sys_rw_content_t \
    '/home/credenza/state(/.*)?'

restorecon -rv /home/credenza/

[[ -r /home/credenza/secrets/globus_client_secret.json ]] \
    || echo WARNING: /home/credenza/secrets/globus_client_secret.json must be populated by the admin

