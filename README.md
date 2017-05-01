# Hetzner hook for `dehydrated`

This is a hook for the [Let's Encrypt](https://letsencrypt.org/) ACME client [dehydrated](https://github.com/lukas2511/dehydrated) (previously known as `letsencrypt.sh`) that allows you to use [Hetzner](https://www.hetzner.de/us/hosting/domain/registrationrobot) DNS records to respond to `dns-01` challenges (credits to [kappataumu](https://github.com/kappataumu/letsencrypt-cloudflare-hook)). Requires Python and your Hetzner account username and password being set as config variables.

## Installation

```
$ cd ~
$ git clone https://github.com/lukas2511/dehydrated
$ cd dehydrated
$ mkdir hooks
$ git clone https://github.com/rembikrain/dehydrated-hetzner-hook hooks/hetzner
$ mkdir hooks/hetzner/zones
```

If you are using Python 3:
```
$ pip3 install -r hooks/hetzner/requirements.txt
```

Otherwise, if you are using Python 2 (make sure to also check the [urllib3 documentation](http://urllib3.readthedocs.org/en/latest/security.html#installing-urllib3-with-sni-support-and-certificates) for possible caveats):

```
$ pip install -r hooks/hetzner/requirements-python-2.txt
```


## Configuration
The hook script is looking for a [`config.json`](https://github.com/rembik/dehydrated-hetzner-hook/blob/master/config.json) in the `hooks/hetzner` directory.
Your account's Hetzner Robot username and password are expected to be in the config variables. Because of the ugly response status codes when requesting Hetzner Robot you also need to specify your Hetzner Robot interface language [english - en | deutsch - de]. So **make sure to set**:

```
"account":{
    "username":"hetzner-robot-user",
    "password":"hetzner-robot-password",
    "language":"en",
    ...
}
```

*Optionally,* you can specify the DNS servers to be used for propagation checking via the `accounts => dns_servers` config variable (credits to [bennettp123](https://github.com/bennettp123)):

```
"account":{
    "dns_servers": [
        "8.8.8.8",
        "8.8.4.4"
    ],
    ...
}
```

*Optionally,* if you want to change the directory for caching the needed `zone` files, change config variable (make sure this directory exists):
 
```
"zone_file_dir":"zones"
```

*Optionally,* if you want more information about what is going on while the hook is running:

```
"debug":true
```

## Usage

```
$ ./dehydrated -c -d example.com -t dns-01 -k 'hooks/hetzner/hook.py'
#
# !! WARNING !! No main config file found, using default config!
#
Processing example.com
 + Signing domains...
 + Creating new directory /home/user/dehydrated/certs/example.com ...
 + Generating private key...
 + Generating signing request...
 + Requesting challenge for example.com...
 + CloudFlare hook executing: deploy_challenge
 + DNS not propagated, waiting 30s...
 + DNS not propagated, waiting 30s...
 + Responding to challenge for example.com...
 + CloudFlare hook executing: clean_challenge
 + Challenge is valid!
 + Requesting certificate...
 + Checking certificate...
 + Done!
 + Creating fullchain.pem...
 + CloudFlare hook executing: deploy_cert
 + ssl_certificate: /home/user/dehydrated/certs/example.com/fullchain.pem
 + ssl_certificate_key: /home/user/dehydrated/certs/example.com/privkey.pem
 + Done!
```


