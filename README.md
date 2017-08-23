# acme_helper

## Requirements

* Python 3

## In production with

* Debian Jessie
* python3 3.4.2
* python3-openssl 0.14
* python3-requests 2.4.3
* python3-yaml 3.11

## Installation
```
apt-get install python3-yaml python3-openssl python3-requests
cd /usr/local
git clone https://github.com/nledez/acme_helper.git
cd /usr/local/acme_helper
mkdir -p /etc/acme-tiny/config.d
cp config.yaml /etc/acme-tiny/
openssl genrsa 4096 > /etc/acme-tiny/account.key
mkdir -p /var/www/letsencrypt
```

## Generate new certificate
```
cd /usr/local/acme_helper
sed 's/www.example.com/www.example.org/g' config-certificate.yaml > /etc/acme-tiny/config.d/www.example.org.yaml
sed 's/www.example.com/www.example.org/g' nginx-sample.conf > /etc/nginx/sites-available/www.example.org.conf
(cd /etc/nginx/sites-enabled ; ln -s ../sites-available/www.example.org.conf .)
/usr/local/acme_helper/acme_helper.py --generate
/usr/local/acme_helper/acme_helper.py
```

## Tune

You can:
* Add/change/remove service(s) in /etc/acme-tiny/config.yaml section "services"
* Add/change/remove service(s) to restart in /etc/acme-tiny/config.d/*.yaml
* Change or custom cron in "/etc/cron.d/acme_helper"
* Change all path in /etc/acme-tiny/config.yaml
* Change commands used to generate private key, CSR & selfsigned certificate

## Notice

You need to launch this:
```
/usr/local/acme_helper/acme_helper.py --generate
```

Before launch this:
```
/usr/local/acme_helper/acme_helper.py
```

The first command create a self signed certificate. It's need for Nginx reload.
And Nginx is need for let's encrypt validataion

## Help

```
/usr/local/acme_helper/acme_helper.py --help
```

## Report

If you have any problem or suggestion:
* https://github.com/nledez/acme_helper/issues
* https://twitter.com/nledez/
