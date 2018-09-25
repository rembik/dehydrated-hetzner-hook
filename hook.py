#!/usr/bin/env python

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
    base_dir = '{0}/hooks/hetzner'.format(os.environ['BASEDIR'])
except KeyError:
    base_dir = '/opt/dehydrated-hetzner-hook'
    logger.error(' + Unable to get dehydrated BASEDIR in environment! Use {0} as base directory instead'.format(base_dir))
try:
    auth_username = os.environ['HETZNER_USERNAME']
    auth_password = os.environ['HETZNER_PASSWORD']
except KeyError:
    logger.error(' + Unable to get Hetzner Robot credentials in environment!')
    sys.exit(1)
try:
    with open('{0}/accounts/{1}.json'.format(base_dir, auth_username), 'r') as f:
        config = json.load(f)
except IOError as e:
    logger.error(' + {0} - config for account "{1}"! Try default hook config instead'.format(e, auth_username))
    try:
        with open('{0}/accounts/default.json'.format(base_dir), 'r') as f:
            config = json.load(f)
    except IOError as e:
        logger.error(' + {0} - Can not load default Hetzner Robot hook config!'.format(e))
        sys.exit(1)  
base_url = 'https://robot.your-server.de'
login_url = 'https://accounts.hetzner.com'
response_check = {'login': {'de': 'Herzlich Willkommen auf Ihrer', 'en': 'Welcome to your'}, 'update': {'de': 'Vielen Dank', 'en': 'Thank you for'}}

if config['debug'] == True:
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)


def _get_nameservers(fld):
    nameservers = []
    default_nameservers = ['8.8.8.8','8.8.4.4']
    logger.debug(' + Checking domain {0} for NS entries'.format(fld))
    try:
        dns_resolver = dns.resolver.Resolver()
        dns_resolver.nameservers = default_nameservers
        dns_ns_response = dns_resolver.query(fld, 'NS')
        for ns in dns_ns_response:
            ns = str(ns)[:-1] if str(ns).endswith('.') else str(ns)
            try:
                dns_ns_ipv4_response = dns_resolver.query(ns, 'A')
                for ns_ipv4 in dns_ns_ipv4_response:
                    ns_ipv4 = str(ns_ipv4)
                    logger.debug('   NS {0} => IPv4 {1}'.format(ns, ns_ipv4))
                    nameservers.append(ns_ipv4)
            except dns.exception.DNSException as e_ns_ipv4:
                logger.debug(' + Could not resolve A entry for NS {0}'.format(ns))
    except dns.exception.DNSException as e_ns:
        logger.debug(' + Could not resolve NS entries for Domain {0}'.format(fld))
    
    return nameservers if nameservers else default_nameservers


def _check_dns_cname(domain):
    nameservers = _get_nameservers(get_tld('http://' + domain))
    challenge = '_acme-challenge.{0}'.format(domain)
    logger.debug(' + Checking domain {0} for valid CNAME entry'.format(challenge))
    try:
        dns_resolver = dns.resolver.Resolver()
        dns_resolver.nameservers = nameservers
        dns_cname_response = dns_resolver.query(challenge, 'CNAME')
        for cname in dns_cname_response:
            cname = str(cname)[:-1] if str(cname).endswith('.') else str(cname)
            if get_tld('http://' + cname, fail_silently=True) != None:
                if cname.startswith('_acme-challenge.'):
                    logger.debug(' + Domain {0} has well-formed CNAME entry {1}'.format(challenge, cname))
                else:
                    logger.debug(' + Domain {0} has valid CNAME entry {1}'.format(challenge, cname))
                    logger.debug(' + WARNING: Better use CNAME target with _acme-challenge. at the beginning!')
                return [domain, cname.encode('UTF-8')]
            else:
                logger.error(' + Domain {0} has invalid CNAME entry {1}'.format(challenge, cname))
                logger.error(' + Need CNAME target with valid top level domain at the end!')
                sys.exit(1)
    except dns.exception.DNSException as e:
        logger.debug(' + Domain {0} has no CNAME entry'.format(challenge))

    return [domain, False]


def _has_dns_propagated(domain, token):
    if domain[1]:
        nameservers = _get_nameservers(get_tld('http://' + domain[1]))
        challenge = domain[1]
    else:
        nameservers = _get_nameservers(get_tld('http://' + domain[0]))
        challenge = '_acme-challenge.{0}'.format(domain[0])
    try:
        dns_resolver = dns.resolver.Resolver()
        dns_resolver.nameservers = nameservers
        dns_txt_response = dns_resolver.query(challenge, 'TXT')
        for txt in dns_txt_response:
            if token in [b.decode('UTF-8') for b in txt.strings]:
                return True
    except dns.exception.DNSException as e:
        logger.debug(' + {0} - Retrying query...'.format(e))
        
    return False


def _login(username, password):
    logger.debug(' + Logging in on Hetzner Robot with account "{0}"'.format(username))
    login_form_url = '{0}/login'.format(login_url)
    login_check_url = '{0}/login_check'.format(login_url)
    session = requests.session()
    session.get(login_form_url)
    r = session.post(login_check_url, data={'_username': username, '_password': password})
    logger.debug(' + Landing on page {0} with status code {1} and cookie {2}'.format(r.url,r.status_code,r.history[0].cookies))
    if '{0}/account/masterdata'.format(login_url) == r.url and r.status_code == 200:
        r = session.get(base_url)
        logger.debug(' + Landing on page {0} with status code {1} and cookie {2}'.format(r.url,r.status_code,r.history[0].cookies))
    # ugly: the hetzner status code is always 200, but redirecting back to the login page form with an "error message".
    if base_url not in r.url or r.status_code != 200:
        logger.error(" + Unable to login with Hetzner credentials from environment!")
        sys.exit(1)
        return
           
    return session
    
    
def _logout(session):
    logger.debug(' + Logging out from Hetzner Robot')
    logout_url = '{0}/login/logout/r/true'.format(base_url)
    r = session.get(logout_url)
    
    return '{0}/logout'.format(login_url) in r.url and r.status_code == 200


def _get_zone_id(domain, session):
    logger.debug(' + Requesting list of zone IDs')
    tld = get_tld('http://' + domain[1]) if domain[1] else get_tld('http://' + domain[0])
    # update zone IDs from config.json, if they are older then one day
    try:
        zone_id_updated = time.strptime(config['zone_ids_updated'], "%d-%m-%YT%H:%M:%S +0000")
    except ValueError:
        zone_id_updated = time.gmtime(0)  
    if (int(time.time()) - int(time.mktime(zone_id_updated))) < 86400:
        zone_ids = {}
        for zone_id in config['zone_ids']:
            zone_ids[zone_id] = config['zone_ids'][zone_id]
        logger.debug(' + Responsed {0} zone IDs'.format(len(zone_ids)))
    else:
        zone_ids = _update_zone_ids(session)   
    
    return zone_ids[tld]


def _extract_zone_id_from_js(s):
    r = re.compile(r'\'(\d+)\'')
    m = r.search(s)
    if not m: return False
    
    return int(m.group(1))
    
    
def _update_zone_ids(session):
    logger.debug(' + Updating list of zone IDs')    
    # delete zone IDs from config
    delete_zone_ids = []
    for zone_id in config['zone_ids']:
        delete_zone_ids.append(zone_id)
    for zone_id in delete_zone_ids:
        del config['zone_ids'][zone_id]
    # get zone IDs from Hetzner Robot
    zone_ids = {}
    last_count = -1
    page = 1
    while last_count != len(zone_ids):
        last_count = len(zone_ids)
        dns_url = '{0}/dns/index/page/{1}'.format(base_url, page)  
        r = session.get(dns_url)
        soup = BeautifulSoup(r.text, 'html5lib')
        boxes = soup.findAll('table', attrs={'class': 'box_title'})
        for box in boxes:
            expandBoxJS = dict(box.attrs)['onclick']
            zone_id = _extract_zone_id_from_js(expandBoxJS)
            tdTag = box.find('td', attrs={'class': 'title'})
            domain = tdTag.renderContents().decode('UTF-8')
            zone_ids[domain] = zone_id
            config['zone_ids'][domain] = zone_id        
        page += 1
    # save zone IDs in config file with current timestamp       
    config['zone_ids_updated'] = time.strftime("%d-%m-%YT%H:%M:%S +0000", time.gmtime())
    with open('{0}/accounts/{1}.json'.format(base_dir, auth_username), 'w') as f:
        json.dump(config, f, indent=4, separators=(',', ': '))    
    logger.debug(' + Updated & responsed {0} zone IDs'.format(len(zone_ids)))
    
    return zone_ids


def _get_zone_file(zone_id, session):
    dns_url = '{0}/dns/update/id/{1}'.format(base_url, zone_id)
    r = session.get(dns_url)
    soup = BeautifulSoup(r.text, 'html5lib')
    inputTag = soup.find('input', attrs={'id': 'csrf_token'})
    csrf_token = inputTag['value']
    textarea = soup.find('textarea', attrs={'id': 'zonefile'})
    zone_file = [csrf_token, textarea.renderContents().decode('UTF-8')]  

    return zone_file


def _edit_zone_file(zone_id, session, domain, token, edit_txt_record):
    if domain[1]:
        tld = get_tld('http://' + domain[1], as_object=True)
        name = '@' if not tld.subdomain else tld.subdomain
        challenge = domain[1]
    else:
        tld = get_tld('http://' + domain[0], as_object=True)
        name = '_acme-challenge' if not tld.subdomain else '{0}.{1}'.format('_acme-challenge', tld.subdomain)
        challenge = '_acme-challenge.{0}'.format(domain[0])
    logger.debug(' + Get zone {0} for TXT record {1} from Hetzner Robot'.format(tld, challenge))
    zone_file = _get_zone_file(zone_id, session)
    logger.debug(' + Searching zone {0} for TXT record {1}'.format(tld, challenge))
    file = os.path.join('{0}/zones'.format(base_dir), '{0}.txt'.format(tld))
    txt_record_regex = re.compile(name + r'\s+IN\s+TXT\s+"'+ token + '"')
    found_txt_record = False
    f = open(file,'w')
    f.write(zone_file[1])
    f.close()
    f = open(file,'r+')
    lines = f.readlines()
    zone_file[1] = ''
    f.seek(0)
    for line in lines:
        if txt_record_regex.search(line):
            found_txt_record = True
            if edit_txt_record=='create':
                logger.debug(' + TXT record for {0} with token {1} allready exists'.format(challenge, token))
            elif edit_txt_record=='delete': 
                logger.debug(' + Deleted TXT record: {0} IN TXT "{1}"'.format(name, token))
                continue
        zone_file[1] = zone_file[1] + line
        f.write(line)
    if not found_txt_record:
        if edit_txt_record=='create':
            logger.debug(' + Unable to locate TXT record for {0}'.format(challenge))
            txt_record = '{0} IN TXT "{1}"'.format(name, token)
            logger.debug(' + Created TXT record: {0}'.format(txt_record))
            zone_file[1] = zone_file[1] + txt_record
            f.write(txt_record)
        else:
            logger.debug(' + TXT record for {0} with token {1} dont exists'.format(challenge, token))
    f.truncate()
    f.close()
    logger.debug(' + Saved zonefile: {0}'.format(file))
    
    return zone_file
    

def _update_zone_file(zone_id, session, zone_file):
    logger.debug(' + Updating zone on Hetzner Robot:\n   id: {0}\n   _csrf_token: {1}\n   zonefile:\n\n{2}\n'.format(zone_id, zone_file[0], zone_file[1]))
    update_url = '{0}/dns/update'.format(base_url)
    r = session.post(
        update_url, 
        data={'id': zone_id, 'zonefile': zone_file[1], '_csrf_token': zone_file[0]}
    )
      
    # ugly: the hetzner status code is always 200 (delivering the update form as an "error message")
    return response_check['update'][config['language']] in r.text


def create_txt_record(args, session):
    domain = args[0]
    token = args[2]
    challenge = domain[1] if domain[1] else '_acme-challenge.{0}'.format(domain[0])
    logger.debug(' + Challenge dns-01: {0} => {1} as TXT record'.format(challenge, token))
    zone_id = _get_zone_id(domain, session)
    zone_file = _edit_zone_file(zone_id, session, domain, token, 'create')
    update_txt_record = _update_zone_file(zone_id, session, zone_file)
    if update_txt_record: 
        logger.debug(' + Updated TXT record for {0} on Hetzner Robot'.format(challenge))
    else:
        logger.error(' + Error during updating zone for {0} on Hetzner Robot!'.format(challenge))
        sys.exit(1)


def delete_txt_record(args, session):
    domain = args[0]
    token = args[2]
    challenge = domain[1] if domain[1] else '_acme-challenge.{0}'.format(domain[0])
    zone_id = _get_zone_id(domain, session)
    zone_file = _edit_zone_file(zone_id, session, domain, token, 'delete')
    delete_txt_record = _update_zone_file(zone_id, session, zone_file)
    if delete_txt_record: 
        logger.debug(' + Deleted TXT record for {0} on Hetzner Robot'.format(challenge))
    else:
        logger.error(' + Error during updating zone for {0} on Hetzner Robot!'.format(challenge))
        sys.exit(1)


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
    session = _login(auth_username, auth_password)  
    X = 3
    for i in range(0, len(args), X):
        args[i] = _check_dns_cname(args[i])
    for i in range(0, len(args), X):
        create_txt_record(args[i:i+X], session)
    # give it 10 seconds to settle down and avoid nxdomain caching
    logger.info(" + Settling down for 10s...")
    time.sleep(10)
    for i in range(0, len(args), X):
        while(_has_dns_propagated(args[i], args[i+2]) == False):
            logger.info(" + DNS not propagated, waiting 30s...")
            time.sleep(30)
    if _logout(session):
        logger.info(' + Hetzner Robot hook finished: deploy_challenge')
    else:
        logger.error(' + Hetzner Robot hook finished (with logout error): deploy_challenge')


def delete_all_txt_records(args):
    session = _login(auth_username, auth_password)
    X = 3
    for i in range(0, len(args), X):
        args[i] = _check_dns_cname(args[i])
    for i in range(0, len(args), X):
        delete_txt_record(args[i:i+X], session)
        # give it 10 seconds to assure zonefile is updated
        logger.info(" + Settling down for 10s...")
        time.sleep(10)
    if _logout(session):
        logger.info(' + Hetzner Robot hook finished: clean_challenge')
    else:
        logger.error(' + Hetzner Robot hook finished (with logout error): clean_challenge')


def startup_hook(args):
    return


def exit_hook(args):
    return


def main(argv):
    ops = {
        'deploy_challenge': create_all_txt_records,
        'clean_challenge' : delete_all_txt_records,
        'deploy_cert'     : deploy_cert,
        'unchanged_cert'  : unchanged_cert,
        'invalid_challenge': invalid_challenge,
        'startup_hook': startup_hook,
        'exit_hook': exit_hook
    }
    if argv[0] in ops:
        logger.info(" + Hetzner Robot hook executing: {0}".format(argv[0]))
        ops[argv[0]](argv[1:])


if __name__ == '__main__':
    main(sys.argv[1:])
