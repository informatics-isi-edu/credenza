
# this ugly hack necessitated by Ubuntu... grrr...
SYSPREFIX=$(shell python3 -c 'import site;print(site.getsitepackages()[0])' | sed -e 's|/[^/]\+/[^/]\+/[^/]\+$$||')
# try to find the architecture-neutral lib dir by looking for one of our expected prereqs... double grrr...
PYLIBDIR=$(shell python3 -c 'import site;import os.path;print([d for d in site.getsitepackages() if os.path.exists(d+"/authlib")][0])')

CONFDIR=/home/credenza/config

ifeq ($(wildcard /etc/httpd/conf.d),/etc/httpd/conf.d)
		HTTPSVC=httpd
else
		HTTPSVC=apache2
endif

HTTPDCONFDIR=/etc/$(HTTPSVC)/conf.d
WSGISOCKETPREFIX=/var/run/$(HTTPSVC)/wsgi
DAEMONUSER=credenza

# turn off annoying built-ins
.SUFFIXES:

INSTALL_SCRIPT=./install-script

# make this the default target
install: config/wsgi_credenza.conf config/oidc_idp_profiles.json config/oidc_idp_trusted_issuers.json
		pip3 install .

testvars:
		@echo DAEMONUSER=$(DAEMONUSER)
		@echo CONFDIR=$(CONFDIR)
		@echo SYSPREFIX=$(SYSPREFIX)
		@echo HTTPDCONFDIR=$(HTTPDCONFDIR)
		@echo WSGISOCKETPREFIX=$(WSGISOCKETPREFIX)
		@echo PYLIBDIR=$(PYLIBDIR)

deploy: install force

redeploy: uninstall deploy

config/wsgi_credenza.conf: config/wsgi_credenza.conf.in force
		./install-script -M sed -R @PYLIBDIR@=$(PYLIBDIR) @WSGISOCKETPREFIX@=$(WSGISOCKETPREFIX) @DAEMONUSER@=$(DAEMONUSER) -o root -g root -m a+r -p -D $< $@

uninstall: force
		-pip3 uninstall -y credenza
		rm -rf /home/${DAEMONUSER}/config
		rm -f ${HTTPDCONFDIR}/wsgi_credenza.conf

force:

