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
certificates, along with a tool called [Certbot] for auto-renewing
certificates. Certbot runs as a cron job, renews certificates when
necessary, and updates your Apache / Nginx configs automatically.
However, certbot grew fairly complicated and requires root privileges.

An alternative tool, [acme-tiny], is a third-party command line tool
that, in UNIX spirit, does one thing and does it well: runs the ACME
protocol and obtains a new SSL cerficiate. It does _not_ require root
privileges, and all of its configuration is straightforward and
completely on the command line. The entire tool is under 200 lines
long, so paranoid users can eyeball the code easily.

However, [acme-tiny] is only one piece of the
puzzle. Our tool, `acme-tiny-cron`, adds the following functionality:

* Configuration for the domains, including (for each domain):
  - Production / staging setting
  - Path to the ACME challenge folder for domain validation
  - Paths to files with CSR (certificate signing request), private
    key, and the resulting certificate
  - When to renew the certificate (how close to the expiration)
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
python3 -m venv ssl
source ssl/bin/activate
./setup.py install
```

### Create CSR requests for each of your domains

For example:

```
openssl req -newkey rsa:2048 -keyout /home/ssl-auto/certs/example.com/private.key \
    -out /home/ssl-auto/certs/example.com/request.csr -nodes
```

For generating CSR without a prompt (non-interactively), use
[-subj](https://www.shellhacks.com/create-csr-openssl-without-prompt-non-interactive/)
or
[-config](http://blog.endpoint.com/2014/10/openssl-csr-with-alternative-names-one.html)
options.

### Create a configuration file

As an example, create a file `~/acme-tiny-cron.cfg` under the user
`ssl-auto`. The file is in Google Protobuf v3 text format. Sample
configuration for two domains:

```proto
// The schema for this config file is at
// https://github.com/sergey-a-berezin/acme-tiny-cron/blob/master/acme_tiny_cron/protos/domains.proto

staging_server:           "https://acme-staging-v02.api.letsencrypt.org"
production_server:        "https://acme-v02.api.letsencrypt.org"
log_path:                 "/var/log/acme/acme_tiny_cron.log"
account_private_key_path: "/home/ssl-auto/private/my_letsencrypt_private.key"

domain: {
  name: "example.com"
  name: "www.example.com"
  mode: STAGING  // Testing the setup; cannot use this cert for real.
  csr_path: "/home/ssl-auto/certs/example.com/request.csr"
  private_key_path: "/home/ssl-auto/certs/example.com/private.key"
  cert_path: "/home/ssl-auto/certs/example.com/cert.crt"
  renew_days_before_expiration: 15  // Optional; default=30
  acme_challenge_path: "/var/www/example.com/.well-known/acme-challenge"
}

domain: {
  name: "my-real-domain.com"
  name: "www.my-real-domain.com"
  mode: PRODUCTION  // This is a real deal
  csr_path: "/home/ssl-auto/certs/my-real-domain.com/request.csr"
  private_key_path: "/home/ssl-auto/certs/my-real-domain.com/private.key"
  cert_path: "/home/ssl-auto/certs/my-real-domain.com/cert.crt"
  renew_days_before_expiration: 15  // Optional; default=30
  acme_challenge_path: "/var/www/my-real-domain.com/.well-known/acme-challenge"
}
```

Note, that [acme-tiny] tool switched to ACME version 2 as of
[Jan 14, 2018](https://github.com/diafygi/acme-tiny/commit/bb248e00125728e6f15806d6408ebd9ac5251cbf),
requiring the use of `*-v02.api.letsencrypt.org` URLs. If your certificate
renewal fails with `KeyError: 'newAccount'`, you are likely still using `*-v01`
versions and need to upgrade.

### Setup file permissions

#### Allow `acme_tiny_cron` write access to the ACME folders

As an example, if your websites are hosted at `/var/www/<domain>/`,
your server runs under `www-data` user, and `acme_tiny_cron` runs
under `ssl-auto`:

```
sudo mkdir -p /var/www/<domain>/.well-known/acme-challenge   # do this for every domain
sudo chown -R www-data /var/www/*/.well-known
sudo chgrp -R ssl-auto /var/www/*/.well-known
sudo chmod g+w -R /var/www/*/.well-known
```

#### Allow web server read access to the certs and domain keys

With similar assumptions as above:

```
sudo chgrp -R www-data /home/ssl-auto/certs
sudo chmod g+r -R /home/ssl-auto/certs
```

#### Hide your account private key

```
chmod 700 -R /home/ssl-auto/private
```

### Configure your web server

Point your server configs for the corresponding domains to look for
the certs and domain private keys. For example, Apache2 configs may
look like this:

```
<IfModule mod_ssl.c>
  <VirtualHost *:443>
        ServerName www.example.com
        DocumentRoot /var/www/example.com
        SSLEngine on
        SSLCertificateFile      /home/ssl-auto/certs/example.com/cert.crt
        SSLCertificateKeyFile   /home/ssl-auto/certs/example.com/private.key
        SSLCACertificateFile    /etc/ssl/certs/letsencrypt_root_bundle.crt

      # <other necessary configuration>

  </VirtualHost>
</IfModule>
```

You can also symlink to the `/home/ssl-auto/certs` folder from
`/etc/ssl` and reference symlinks from the web server config.

### Setup a cron job

Add the following to your root crontab:

```
crontab <<EOF
SHELL=/bin/sh

0 0 * * *    sudo -u -H ssl-auto /home/ssl-auto/ssl/bin/acme-tiny-cron /home/ssl-auto/acme-tiny-cron.cfg && service apache2 reload
EOF
```

Note, that the script takes its config file as the only argument, and
returns success (code 0) only when at least one certificate was issued
or renewed. This way, it is safe to run this cron job daily or even
hourly without needlessly restarting the web server.
