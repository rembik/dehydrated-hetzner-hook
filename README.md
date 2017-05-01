# Hetzner Robot hook for `dehydrated`

This is a hook for the [Let's Encrypt](https://letsencrypt.org/) ACME client [dehydrated](https://github.com/lukas2511/dehydrated) (previously known as `letsencrypt.sh`) that allows you to use [Hetzner](https://www.hetzner.de/us/hosting/domain/registrationrobot) DNS records to respond to `dns-01` challenges (credits to [kappataumu](https://github.com/kappataumu/letsencrypt-cloudflare-hook)). Requires Python and your Hetzner Robot account(username and password) being set as config variables.

## Precondition
```
sudo su
mkdir /etc/dehydrated
cd /etc/dehydrated
mkdir certs accounts hooks
cd /opt
git clone https://github.com/lukas2511/dehydrated.git
cd dehydrated
cp docs/examples/config /etc/dehydrated/
cp docs/examples/domains.txt /etc/dehydrated/
ln -s /opt/dehydrated/dehydrated /usr/local/bin/
```

## Installation

```
$ cd /opt/
$ git clone https://github.com/rembik/dehydrated-hetzner-hook
$ cp dehydrated-hetzner-hook/config.default.json dehydrated-hetzner-hook/config.json
$ ln -s /opt/dehydrated-hetzner-hook/ /etc/dehydrated/hooks/hetzner
```
If you are using the recommended Python 3:
```
$ apt install python3 python3-pip
$ pip3 install -r dehydrated-hetzner-hook/requirements.txt
```
Otherwise, if you are using Python 2 (make sure to also check the [urllib3 documentation](http://urllib3.readthedocs.org/en/latest/security.html#installing-urllib3-with-sni-support-and-certificates) for possible caveats):
```
$ apt install python python-pip
$ pip install -r dehydrated-hetzner-hook/requirements-python-2.txt
```
In dehydrated-hetzner-hook/hook.py change the top line to point at python2.
```
#!/usr/bin/env python
```

## Configuration
Edit the `/etc/dehydrated/config` file, add/uncomment the following lines:
```
BASEDIR="/etc/dehydrated"
CHALLENGETYPE="dns-01"
CERTDIR="${BASEDIR}/certs"
ACCOUNTDIR="${BASEDIR}/accounts"
HOOK="${BASEDIR}/hooks/hetzner/hook.py"
CONTACT_EMAIL="youremail@example.com"
```

The hook script is looking for a [`config.json`](https://github.com/rembik/dehydrated-hetzner-hook/blob/master/config.default.json) and a directory `zones` in the `${BASEDIR}/hooks/hetzner` directory.
Your account's Hetzner Robot username and password are expected to be in the config file. Because of the ugly response status codes when requesting Hetzner Robot you also need to specify your Hetzner Robot interface language [english - en | deutsch - de]. So **make sure to set**:
```
"account": {
    "username": "hetzner-robot-user",
    "password": "hetzner-robot-password",
    "language": "en",
    ...
}
```

*Optionally,* but **highly recommended**: Specify your Hetzner Nameservers (see your DNS `zone` files) to be used for propagation checking via the `accounts => dns_servers` config variable (credits to [bennettp123](https://github.com/bennettp123)):
```
"account": {
    "dns_servers": [
        "213.239.242.238",
        "213.133.105.6",
        "193.47.99.3"
    ],
    ...
}
```

*Optionally,* if you want more information about what is going on while the hook is running:
```
"debug": true
```

## Usage
Edit the `/etc/dehydrated/domains.txt` file, add something like this:
```
example.com
example.org www.example.org dev.example.org
```

```
$ dehydrated -c
Processing example.com
 + Signing domains...
 + Generating private key...
 + Generating signing request...
 + Requesting challenge for example.com...
 + Hetzner Robot hook executing: deploy_challenge
 + Settling down for 10s...
 + None of DNS query names exist: _acme-challenge.example.com., _acme-challenge.example.com. - Retrying query...
 + DNS not propagated, waiting 30s...
 + None of DNS query names exist: _acme-challenge.example.com., _acme-challenge.example.com. - Retrying query...
 + DNS not propagated, waiting 30s...
 + None of DNS query names exist: _acme-challenge.example.com., _acme-challenge.example.com. - Retrying query...
 + DNS not propagated, waiting 30s...
 + None of DNS query names exist: _acme-challenge.example.com., _acme-challenge.example.com. - Retrying query...
 + DNS not propagated, waiting 30s...
 + Responding to challenge for example.com...
 + Hetzner Robot hook executing: clean_challenge
 + Challenge is valid!
 + Requesting certificate...
 + Checking certificate...
 + Done!
 + Creating fullchain.pem...
 + Hetzner Robot hook executing: deploy_cert
 + ssl_certificate: /home/user/dehydrated/certs/example.com/fullchain.pem
 + ssl_certificate_key: /home/user/dehydrated/certs/example.com/privkey.pem
 + Done!
 + Hetzner Robot hook executing: exit_hook
```


