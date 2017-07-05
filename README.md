# acme-tiny-cron

[acme-tiny]: https://github.com/diafygi/acme-tiny
[LetsEncrypt.org]: https://letsencrypt.org
[Certbot]: https://github.com/certbot/certbot

A cron script wrapper around [acme-tiny] for auto-renewing SSL
certificates with LetsEncrypt.org.

This script does _not_ require root privileges to renew SSL
certificates.

## What it does

If you self-host websites and you want to secure them with SSL,
[LetsEncrypt.org] provides a free API for issuing and renewing SSL
certificates, also offer a [Certbot] tool for auto-renewing
certificates. It runs as a cron job, renews certificates only when
necessary, and updates your Apache / Nginx configs automatically.
Unfortunately, [Certbot] grew fairly complicated and requires root
privileges.

An alternative [acme-tiny] is a third-party command line tool that
does only one thing and does it well: runs the ACME protocol and
obtains a new SSL cerficiate for you. It does _not_ require root
privileges, all of its configuration is completely on the command
line, and it's under 200 lines long, so paranoid users can eyeball the
code easily.

However, [acme-tiny] is only one piece of the
puzzle. Our tool, `acme-tiny-cron`, adds the following functionality:

* Configuration for the domains, including (for each domain):
  - Production / staging setting
  - Path to the ACME folder for domain validation
  - Path to CSR (certificate signing request) file, etc.
* A script suitable to run in a cron job at high frequency (e.g. once
  a day or once an hour).
  - Certificates will only be renewed when they are approaching their
     expiration date.

## Requirements

* Python 2.7 or 3.5+
* OpenSSL

## Installation

We strongly recommend to create a dedicated user on your server,
e.g. `ssl-auto`, and install the tool under this user's home directory.

### Install the python package

We recommend installing in a virtualenv, to isolate the dependencies
from other global system installations:

```
python -m venv ssl
source ssl/bin/activate
./setup.py install
```

### Allow `ssl-auto` user write access to the ACME folders

E.g., if your websites are hosted at `/var/www/<domain>/`, and your
server runs as `www-data` user:

```
sudo mkdir /var/www/<domain>/.well-known   # do this for every domain
sudo chown -R www-data /var/www/*/.well-known
sudo chgrp -R ssl-auto /var/www/*/.well-known
sudo chmod g+w -R ssl-auto /var/www/*/.well-known
```

### Create CSR requests for each of your domains

E.g.:

```
openssl req -newkey rsa:2048 -keyout example.com-private.key \
    -out example.com-request.csr -nodes
```

For generating CSR without a prompt (non-interactively),
([use -subj](https://www.shellhacks.com/create-csr-openssl-without-prompt-non-interactive/)
or
[-config](http://blog.endpoint.com/2014/10/openssl-csr-with-alternative-names-one.html))
options.

### Create a configuration file

<TODO: write this>

E.g. create a file `~/acme-tiny-cron.cfg`. The file is in Google
Protobuf v3 text format.

### Setup a cron job

Add the following to your root crontab:

```
crontab <<EOF
SHELL=/bin/sh

0 0 * * *    sudo -u -H ssl-auto /home/ssl-auto/ssl/bin/acme-tiny-cron /home/ssl-auto/acme-tiny-cron.cfg && service apache2 restart
EOF
```

Note, that the script takes its config file as the only argument, and
returns success (code 0) only when at least one certificate was issued
or renewed. This way, it is safe to run this cron job daily or even
hourly without needlessly restarting the web server.
