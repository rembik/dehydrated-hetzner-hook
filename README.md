# `DEPRECATED` Hetzner hook for `dehydrated`

*This hook is considered deprecated after being integrated into the Python DNS library [lexicon](https://github.com/AnalogJ/lexicon).*

[![GitHub release](https://img.shields.io/github/release/rembik/dehydrated-hetzner-hook.svg)](https://github.com/rembik/dehydrated-hetzner-hook/releases)
[![PyPI version](https://img.shields.io/pypi/pyversions/dns-lexicon.svg)](https://github.com/rembik/dehydrated-hetzner-hook/blob/master/hook.py)
[![GitHub license](https://img.shields.io/github/license/rembik/dehydrated-hetzner-hook.svg)](https://github.com/rembik/dehydrated-hetzner-hook/blob/master/LICENSE.md)

This is a hook for the [Let's Encrypt](https://letsencrypt.org/) ACME client [dehydrated](https://github.com/lukas2511/dehydrated) (previously known as `letsencrypt.sh`) that allows you to use [Hetzner Robot](https://www.hetzner.com/registrationrobot) or [Hetzner konsoleH](https://www.hetzner.com/domainregistration) DNS to respond to `dns-01` challenges. Requires Python and Hetzner account credentials (specified as environment variables).

## Precondition
```shell
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

```shell
sudo su
cd /opt/
git clone https://github.com/rembik/dehydrated-hetzner-hook.git
ln -s /opt/dehydrated-hetzner-hook/ /etc/dehydrated/hooks/hetzner
```
Assuming `python` and ` pip` already exists on the system, install the necessary packages and make sure the first line (`#!/usr/bin/env python`) in `hook.py` points to the provided Python interpreter:
```shell
pip install -r dehydrated-hetzner-hook/requirements.txt
```

## Configuration
Edit the `/etc/dehydrated/config` file, add/uncomment the following lines:
```
BASEDIR="/etc/dehydrated"
CHALLENGETYPE="dns-01"
HOOK="${BASEDIR}/hooks/hetzner/hook.py"
HOOK_CHAIN="yes"
CONTACT_EMAIL="admin@example.com"
```
Specify Hetzner account, username and password as environment variables. 
As defaults add these lines to the `/etc/dehydrated/config` file:
```
# Hetzner account: by default Hetzner Robot (robot) or Hetzner konsoleH (konsoleh)
#export HETZNER_AUTH_ACCOUNT='robot'
export HETZNER_AUTH_USERNAME='<username>'
export HETZNER_AUTH_PASSWORD='<password>'
```
*Optional*, specify Hetzner log level as environment variable.
```
# Hetzner log level: by default INFO (choose from CRITICAL, ERROR, WARNING, INFO, DEBUG or NOTSET)
#export HETZNER_LOG_LEVEL=INFO
```
*Optional*, in environments with more than one DNS provider and/or account for `dns-01` challenging, specify authentication parameters on execution: 
```shell
HETZNER_AUTH_ACCOUNT='robot' HETZNER_AUTH_USERNAME='<username>' HETZNER_AUTH_PASSWORD='<password>' dehydrated -c -d 'example.org example.net *.example.org' -t 'dns-01' -k '/etc/dehydrated/hooks/hetzner/hook.py'
```
*Optional*, for `CNAME dns-01` challenges add a CNAME entry from the 
requested domain to the Hetzner domain that should accomplish the dns challenge. 
The CNAME for dns-01 challenging `example.net` with `example.org` could look 
similar to the following and must be added to the domain `example.net`: 
```
_acme-challenge    IN CNAME   localhost.example.org.
```

## Usage
For example specified `/etc/dehydrated/domains.txt`
```
example.org example.net *.example.org
```

will look similar to the following on execution:
```
dehydrated -c
 + Checking domain name(s) of existing cert... unchanged.
 + Checking expire date of existing cert...
 + Valid till Jan 01 00:00:00 2019 GMT (Less than 30 days).
 + Signing domains...
 + Generating private key...
 + Generating signing request...
 + Requesting new certificate order from CA...
 + Received 3 authorizations URLs from the CA
 + Handling authorization for example.org
 + Handling authorization for example.net
 + Handling authorization for example.org
 + 3 pending challenge(s)
 + Deploying challenge tokens...
 + Hetzner hook executing deploy_challenge...
Hetzner => Enable CNAME lookup (see --linked parameter)
Hetzner => Authenticate session with robot account '<username>'
Hetzner => Get ID 123456 for domain example.org
Hetzner => Exit session
Hetzner => Enable CNAME lookup (see --linked parameter)
Hetzner => Authenticate session with robot account '<username>'
Hetzner => Get zone for domain example.org
Hetzner => Update zone for domain example.org
Hetzner => Wait 30s until Hetzner Robot has taken over zone...
Hetzner => Exit session
Hetzner => Enable CNAME lookup (see --linked parameter)
Hetzner => Record _acme-challenge.example.net. has CNAME localhost.example.org.
Hetzner => Authenticate session with robot account '<username>'
Hetzner => Get ID 123456 for domain example.org
Hetzner => Exit session
Hetzner => Enable CNAME lookup (see --linked parameter)
Hetzner => Record _acme-challenge.example.net. has CNAME localhost.example.org.
Hetzner => Authenticate session with robot account '<username>'
Hetzner => Get ID 123456 for domain example.org
Hetzner => Get zone for domain example.org
Hetzner => Update zone for domain example.org
Hetzner => Wait 30s until Hetzner Robot has taken over zone...
Hetzner => Exit session
Hetzner => Enable CNAME lookup (see --linked parameter)
Hetzner => Authenticate session with robot account '<username>'
Hetzner => Get ID 123456 for domain example.org
Hetzner => Exit session
Hetzner => Enable CNAME lookup (see --linked parameter)
Hetzner => Authenticate session with robot account '<username>'
Hetzner => Get zone for domain example.org
Hetzner => Update zone for domain example.org
Hetzner => Wait 30s until Hetzner Robot has taken over zone...
Hetzner => Record is not propagated, retry (2/20) in 30s...
Hetzner => Record is not propagated, retry (3/20) in 30s...
Hetzner => Record is not propagated, retry (4/20) in 30s...
Hetzner => Record is not propagated, retry (5/20) in 30s...
Hetzner => Record is not propagated, retry (6/20) in 30s...
Hetzner => Record is not propagated, retry (7/20) in 30s...
Hetzner => Record is not propagated, retry (8/20) in 30s...
Hetzner => Record is not propagated, retry (9/20) in 30s...
Hetzner => Record is not propagated, retry (10/20) in 30s...
Hetzner => Record _acme-challenge.example.org. has TXT "vo0zrBpj3rKiAb75mlaVSUeiFlZUe2-q2nNe_RQpn2Q"
Hetzner => Exit session
 + Responding to challenge for example.org authorization...
 + Challenge is valid!
 + Responding to challenge for example.net authorization...
 + Challenge is valid!
 + Responding to challenge for example.org authorization...
 + Challenge is valid!
 + Cleaning challenge tokens...
 + Hetzner hook executing clean_challenge...
Hetzner => Enable CNAME lookup (see --linked parameter)
Hetzner => Authenticate session with robot account '<username>'
Hetzner => Get ID 123456 for domain example.org
Hetzner => Exit session
Hetzner => Enable CNAME lookup (see --linked parameter)
Hetzner => Authenticate session with robot account '<username>'
Hetzner => Get zone for domain example.org
Hetzner => Update zone for domain example.org
Hetzner => Wait 30s until Hetzner Robot has taken over zone...
Hetzner => Exit session
Hetzner => Enable CNAME lookup (see --linked parameter)
Hetzner => Record _acme-challenge.example.net. has CNAME localhost.example.org.
Hetzner => Authenticate session with robot account '<username>'
Hetzner => Get ID 123456 for domain example.org
Hetzner => Exit session
Hetzner => Enable CNAME lookup (see --linked parameter)
Hetzner => Record _acme-challenge.example.net. has CNAME localhost.example.org.
Hetzner => Authenticate session with robot account '<username>'
Hetzner => Get ID 123456 for domain example.org
Hetzner => Get zone for domain example.org
Hetzner => Update zone for domain example.org
Hetzner => Wait 30s until Hetzner Robot has taken over zone...
Hetzner => Exit session
Hetzner => Enable CNAME lookup (see --linked parameter)
Hetzner => Authenticate session with robot account '<username>'
Hetzner => Get ID 123456 for domain example.org
Hetzner => Exit session
Hetzner => Enable CNAME lookup (see --linked parameter)
Hetzner => Authenticate session with robot account '<username>'
Hetzner => Get zone for domain example.org
Hetzner => Update zone for domain example.org
Hetzner => Wait 30s until Hetzner Robot has taken over zone...
Hetzner => Exit session
 + Requesting certificate...
 + Checking certificate...
 + Done!
 + Creating fullchain.pem...
 + Hetzner hook executing deploy_cert...
 + Done!
 + Hetzner hook executing exit_hook...
```
