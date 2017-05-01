#!/usr/bin/env python3

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from builtins import str

from future import standard_library
standard_library.install_aliases()

import dns.exception
import dns.resolver
import logging
import os
import requests
import sys
import time
import re
import json

from tld import get_tld
from bs4 import BeautifulSoup

# Enable verified HTTPS requests on older Pythons
# http://urllib3.readthedocs.org/en/latest/security.html
if sys.version_info[0] == 2:
    try:
        requests.packages.urllib3.contrib.pyopenssl.inject_into_urllib3()
    except AttributeError:
        # see https://github.com/certbot/certbot/issues/1883
        import urllib3.contrib.pyopenssl
        urllib3.contrib.pyopenssl.inject_into_urllib3()

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())

try:
    with open('config.json', 'r') as f:
        config = json.load(f)
except IOError as e:
    logger.error('{0}. during loading "config.json"!'.format(e))

if config['debug'] == True:
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)


def _has_dns_propagated(name, token):
    dns_servers = []    
    for dns_server in config['account']['dns_servers']:
        dns_servers.append(dns_server)   
    if not dns_servers:
        dns_servers = False      
    try:
        if dns_servers:
            custom_resolver = dns.resolver.Resolver()
            custom_resolver.nameservers = dns_servers
            dns_response = custom_resolver.query(name, 'TXT')
        else:
            dns_response = dns.resolver.query(name, 'TXT')
            
        for rdata in dns_response:
            if token in [b.decode('utf-8') for b in rdata.strings]:
                return True            
    except dns.exception.DNSException as e:
        logger.debug(" + {0}. Retrying query...".format(e))
        
    return False


def _login(username, password, language):
    logger.debug(' + Logging in on Hetzner Robot with account "{0}"'.format(config['account']['username']))
    login_form_url = config['base_url'] + '/login'
    login_url = config['base_url'] + '/login/check'
    r = requests.get(login_form_url)
    r = requests.post(login_url, data={'user': username, 'password': password}, cookies=r.cookies)
    # ugly: the hetzner status code is always 200 (delivering the login form as an "error message")
    if config['response_check']['login'][language] not in r.text:
        logger.error(" + Unable to login with Hetzner credentials from config!")
        sys.exit(1)
        return
        
    logger.debug(' + Logged in.')    
    return r.history[0].cookies
    
    
def _logout(cookies):
    logger.debug(' + Logging out from Hetzner Robot')
    logout_url = config['base_url'] + '/login/logout'
    r = requests.get(logout_url, cookies=cookies)
    
    return r.status_code == 200


def _get_zone_id(domain, cookies):
    logger.debug(' + Requesting list of zone IDs')
    tld = get_tld('http://' + domain)    
    # update zone IDs from config.json, if they are older then one day
    try:
        zone_id_updated = time.strptime(config['account']['zone_ids_updated'], "%d-%m-%YT%H:%M:%S +0000")
    except ValueError:
        zone_id_updated = time.gmtime(0)  
    if (int(time.time()) - int(time.mktime(zone_id_updated))) < 86400:
        for zone_id in config['account']['zone_ids']:
            zone_ids[zone_id] =  config['account']['zone_ids'][zone_id]
        logger.debug(' + Responsed {0} zone IDs.'.format(len(zone_ids)))
    else:
        zone_ids = _update_zone_ids(cookies)   
    
    return zone_ids[tld]


def _extract_zone_id_from_js(s):
    r = re.compile('\'(\d+)\'')
    m = r.search(s)
    if not m: return False
    
    return int(m.group(1))
    
    
def _update_zone_ids(cookies):
    logger.debug(' + Updating list of zone IDs')    
    # delete zone IDs from config.json
    delete_zone_ids = []
    for zone_id in config['account']['zone_ids']:
        delete_zone_ids.append(zone_id)
    for zone_id in delete_zone_ids:
        del config['account']['zone_ids'][zone_id]
    # get zone IDs from Hetzner Robot
    zone_ids = {}
    last_count = -1
    page = 1
    while last_count != len(zone_ids):
        last_count = len(zone_ids)
        dns_url = config['base_url'] + '/dns/index/page/%i' % page  
        r = requests.get(dns_url, cookies=cookies)
        soup = BeautifulSoup(r.text, 'html5lib')
        boxes = soup.findAll('table', attrs={'class': 'box_title'})
        for box in boxes:
            expandBoxJS = dict(box.attrs)['onclick']
            zone_id = _extract_zone_id_from_js(expandBoxJS)
            tdTag = box.find('td', attrs={'class': 'title'})
            domain = tdTag.renderContents().decode('UTF-8')
            zone_ids[domain] = zone_id
            config['account']['zone_ids'][domain] = zone_id        
        page += 1
    # save zone IDs in config.json with current timestamp       
    config['account']['zone_ids_updated'] = time.strftime("%d-%m-%YT%H:%M:%S +0000", time.gmtime())
    with open('config.json', 'w') as f:
        json.dump(config, f, indent=4, separators=(',', ': '))    
    logger.debug('Updated & responsed {0} zone IDs'.format(len(zone_ids)))
    
    return zone_ids


def _get_zone_file(zone_id, cookies):
    dns_url = config['base_url'] + '/dns/update/id/%i' % id
    r = requests.get(dns_url, cookies=cookies)
    soup = BeautifulSoup(r.text, 'html5lib')
    inputTag = soup.find('input', attrs={'id': 'csrf_token'})
    csrf_token = inputTag['value']
    textarea = soup.find('textarea', attrs={'id': 'zonefile'})
    zone_file = [csrf_token, textarea.renderContents().decode('UTF-8')]  

    return zone_file


def _edit_zone_file(zone_id, cookies, domain, token, edit_txt_record):
    tld = get_tld('http://' + domain)
    name = '{0}.{1}'.format('_acme-challenge', tld.subdomain)
    logger.debug(' + Get zone {0} for TXT record {1} from Hetzner Robot'.format(tld, name))
    zone_file = _get_zone_file(zone_id, cookies)
    logger.debug(' + Searching zone {0} for TXT record {1}'.format(tld, name))
    file = os.path.join(config['zone_file_dir'], '{0}.txt'.format(tld))
    txt_record_regex = re.compile('\'' + name + '\s+IN\s+TXT\s+'+ token +'\'')
    found_txt_record = False
    f = open(file,'wr+')
    f.write(zone_file[1])
    f.seek(0)
    lines = f.readlines()
    f.seek(0)
    for line in lines:
        if txt_record_regex.search(line):
            found_txt_record = True
            if edit_txt_record=='create':
                logger.debug(' + TXT record for {0} with token {1} allready exists'.format(name, token))
            elif edit_txt_record=='delete': 
                logger.debug(' + Deleted TXT record "{0} IN TXT {1}"'.format(name, token))
                continue
        f.write(line)
        zone_file[1] = ''.join(line)
    if not found_txt_record:
        if edit_txt_record=='create':
            logger.debug(' + Unable to locate TXT record for {0}'.format(name))
            txt_record = '{0} IN TXT {1}'.format(name, token)
            logger.debug(' + Created TXT record "{0}"'.format(txt_record))
            zone_file[1] = ''.join(txt_record)
        else:
            logger.debug(' + No TXT record for {0} with token {1}'.format(name, token))
    f.truncate()
    f.close()
    logger.debug(' + Saved zonefile: {0}'.format(file))
    
    return zone_file
    

def _update_zone_file(id, cookies, zone_file, language):
    logger.debug('Updating zone on Hetzner Robot:\n   cookies: {0}\n   ID: {1}\n   Zonefile:\n{2}\n   _csrf_token: {3}'.format(cookies, id, zone_file[1], zone_file[0]))
    update_url = config['base_url'] + '/dns/update'
    r = requests.post(
        update_url, 
        cookies=cookies, 
        data={'id': id, 'zonefile': zone_file[1], '_csrf_token': zone_file[0]}
    )
    
    # ugly: the hetzner status code is always 200 (delivering the login form as an "error message")
    return config['response_check']['update'][language] in r.text


def create_txt_record(args, cookies):
    domain, challenge, token = args
    logger.debug(' + Creating TXT record: {0} => {1}'.format(domain, token))
    logger.debug(' + Challenge: {0}'.format(challenge))
    zone_id = _get_zone_id(domain, cookies)
    zone_file = _edit_zone_file(zone_id, cookies, domain, token, 'create')
    update_succeed = _update_zone_file(zone_id, cookies, zone_file, config['account']['language'])
    if update_succeed: 
        logger.debug(' + Updated TXT record for {0} successfully'.format(domain))
    else:
        logger.error(' + Error during updating TXT record for {0}!'.format(domain))


def delete_txt_record(args, cookies):
    domain, token = args[0], args[2]
    if not domain:
        logger.info(" + http_request() error in letsencrypt.sh?")
        return

    zone_id = _get_zone_id(domain, cookies)
    zone_file = _edit_zone_file(zone_id, cookies, domain, token, 'delete')
    update_succeed = _update_zone_file(zone_id, cookies, zone_file, config['account']['language'])
    if update_succeed: 
        logger.debug(' + Updated TXT record for {0} successfully'.format(domain))
    else:
        logger.error(' + Error during updating TXT record for {0}!'.format(domain))


def deploy_cert(args):
    domain, privkey_pem, cert_pem, fullchain_pem, chain_pem, timestamp = args
    logger.debug(' + ssl_certificate: {0}'.format(fullchain_pem))
    logger.debug(' + ssl_certificate_key: {0}'.format(privkey_pem))
    return


def unchanged_cert(args):
    return
    

def invalid_challenge(args):
    domain, result = args
    logger.debug(' + invalid_challenge for {0}'.format(domain))
    logger.debug(' + Full error: {0}'.format(result))
    return


def create_all_txt_records(args):
    cookies = _login(config['account']['username'], config['account']['password'], config['account']['language'])  
    X = 3
    for i in range(0, len(args), X):
        create_txt_record(args[i:i+X], cookies)
    # give it 10 seconds to settle down and avoid nxdomain caching
    logger.info(" + Settling down for 10s...")
    time.sleep(10)
    for i in range(0, len(args), X):
        domain, token = args[i], args[i+2]
        name = "{0}.{1}".format('_acme-challenge', domain)
        while(_has_dns_propagated(name, token) == False):
            logger.info(" + DNS not propagated, waiting 30s...")
            time.sleep(30)
    if not _logout(cookies):
        logger.debug(' + Can not logout!')
    else:
        logger.debug(' + Logged out.')


def delete_all_txt_records(args):
    cookies = _login(config['account']['username'], config['account']['password'], config['account']['language'])
    X = 3
    for i in range(0, len(args), X):
        delete_txt_record(args[i:i+X], cookies)
    if not _logout(cookies):
        logger.debug(' + Can not logout!')
    else:
        logger.debug(' + Logged out.')


def exit_hook(args):
    return


def main(argv):
    ops = {
        'deploy_challenge': create_all_txt_records,
        'clean_challenge' : delete_all_txt_records,
        'deploy_cert'     : deploy_cert,
        'unchanged_cert'  : unchanged_cert,
        'invalid_challenge': invalid_challenge,
        'exit_hook': exit_hook
    }
    logger.info(" + Hetzner hook executing: {0}".format(argv[0]))
    ops[argv[0]](argv[1:])


if __name__ == '__main__':
    main(sys.argv[1:])
