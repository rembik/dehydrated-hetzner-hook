# Hetzner Robot hook for `dehydrated`

This is a hook for the [Let's Encrypt](https://letsencrypt.org/) ACME client [dehydrated](https://github.com/lukas2511/dehydrated) (previously known as `letsencrypt.sh`) that allows you to use [Hetzner](https://www.hetzner.de/us/hosting/domain/registrationrobot) DNS records to respond to `dns-01` challenges (credits to [kappataumu](https://github.com/kappataumu/letsencrypt-cloudflare-hook)). Requires Python and your Hetzner Robot account (username and password) being set as environment variables.

## Precondition
```
$ sudo su
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
$ sudo su \
cd /opt/ \
git clone https://github.com/rembik/dehydrated-hetzner-hook.git
ln -s /opt/dehydrated-hetzner-hook/ /etc/dehydrated/hooks/hetzner
```
If you are using the recommended Python 3:
```
$ sudo su \
apt-get install python3 python3-pip
pip3 install -r dehydrated-hetzner-hook/requirements.txt
```
and dehydrated-hetzner-hook/hook.py change the top line to point at `python3`:
```
#!/usr/bin/env python3
```
Otherwise, if you are using Python 2 (make sure to also check the [urllib3 documentation](http://urllib3.readthedocs.org/en/latest/security.html#installing-urllib3-with-sni-support-and-certificates) for possible caveats):
```
$ sudo su \
apt-get install python python-dev python-pip
pip install -r dehydrated-hetzner-hook/requirements-python-2.txt
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
Your account's Hetzner Robot username and password are expected to be environment variables. As defaults add these lines to the `/etc/dehydrated/config` file:
```
export HETZNER_USERNAME='your-hetzner-user'
export HETZNER_PASSWORD='your-hetzner-password'
```
The hook script is looking for a config file `accounts/${HETZNER_USERNAME}.json` and a directory `zones` in the `${BASEDIR}/hooks/hetzner` directory. If no config file for your account exists, the script will create one with the variables from [`accounts/default.json`](https://github.com/rembik/dehydrated-hetzner-hook/blob/master/accounts/default.json).

Because of the ugly response status codes when requesting Hetzner Robot you also need to specify your Hetzner Robot interface language [english - en | deutsch - de]. So **make sure to set** your default language in `default.json`:
```
{
    "language": "de",
    ...
}
```

*Optionally,* but **highly recommended**: Customize your default Hetzner Nameservers (see your DNS `zone` files) in `default.json` to be used for propagation checking (credits to [bennettp123](https://github.com/bennettp123)):
```
{
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
 + Hetzner Robot hook finished: deploy_challenge
 + Responding to challenge for example.com...
 + Hetzner Robot hook executing: clean_challenge
 + Hetzner Robot hook finished: clean_challenge
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

In environments with more than one DNS provider and/or account for `dns-01` challenging, use: 
```
$ HETZNER_USERNAME='your-hetzner-user' HETZNER_PASSWORD='your-hetzner-password' dehydrated -c -d 'example.com' -t 'dns-01' -k '/etc/dehydrated/hooks/hetzner/hook.py'
```

