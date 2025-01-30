 """

# Author: John Kennedy
# Email: kissotdragon@gmail.com
# Date: 01/29/2025
"""
#! python3
import requests
import untangle
import xmltodict
import json
import lxml
import pprint
import sys
import socket
import collections
import os
import types
import re
import io
import time
from datetime import datetime, timedelta
import pytz
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from optparse import OptionParser, BadOptionError, AmbiguousOptionError
import libtaxii as t
import libtaxii.messages_11 as tm11
import libtaxii.clients as tc
from libtaxii.common import generate_message_id
from libtaxii.constants import *
from stix.core import STIXPackage, STIXHeader
from stix.utils.parser import EntityParser
from stix.common import vocabs
from stix.common.vocabs import VocabString, IndicatorType
from dateutil.tz import tzutc
from lxml import etree
from xml.etree import ElementTree as ET

# Constants and Configuration
CONFIG = {
    'FACILITY': {
        'kern': 0, 'user': 1, 'mail': 2, 'daemon': 3,
        'auth': 4, 'syslog': 5, 'lpr': 6, 'news': 7,
        'uucp': 8, 'cron': 9, 'authpriv': 10, 'ftp': 11,
        'local0': 16, 'local1': 17, 'local2': 18, 'local3': 19,
        'local4': 20, 'local5': 21, 'local6': 22, 'local7': 23,
    },
    'LEVEL': {
        'emerg': 0, 'alert': 1, 'crit': 2, 'err': 3,
        'warning': 4, 'notice': 5, 'info': 6, 'debug': 7
    },
    'DESTINATION_IP': {
        'ip': '10.0.0.21',
        'port': '514',
    }
}

socket.setdefaulttimeout(30)

# Set Proxy
PROXY_DICT = {
    "http": os.getenv("HTTP_PROXY"),
    "https": os.getenv("HTTPS_PROXY"),
    "ftp": os.getenv("FTP_PROXY")
}

def send_syslog(message, level=CONFIG['LEVEL']['notice'], facility=CONFIG['FACILITY']['daemon'], host='localhost', port=1514):
    """
    Send syslog message.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        data = f'<{level + facility * 8}>{message}'
        sock.sendto(data.encode('utf-8'), (host, port))

def create_poll_request(start_time, end_time):
    """
    Create TAXII poll request.
    """
    poll_req = tm11.PollRequest(
        message_id=tm11.generate_message_id(),
        collection_name='system.Default',
        exclusive_begin_timestamp_label=start_time,
        inclusive_end_timestamp_label=end_time,
        poll_parameters=tm11.PollRequest.PollParameters()
    )
    return poll_req.to_xml()

def parse_observables(soup):
    """
    Parse observables from XML.
    """
    for child in soup.find_all('Observables'):
        try:
            if child.Observable:
                handle_observable(child.Observable)
        except (TypeError, AttributeError, KeyError):
            pass

def parse_indicators(soup):
    """
    Parse indicators from XML.
    """
    for child in soup.find_all('Indicators'):
        try:
            if child.Indicator:
                handle_indicator(child.Indicator)
        except (TypeError, AttributeError, KeyError):
            pass

def handle_observable(observable):
    """
    Handle different types of observables.
    """
    if 'e-mail' in observable.Properties.get("category", ""):
        process_email_observable(observable)
    elif 'ipv4-addr' in observable.Properties.get("category", ""):
        process_ip_observable(observable)
    elif 'URL' in observable.Properties.get("type", ""):
        process_url_observable(observable)
    elif 'FileObj:FileObjectType' in observable.Properties.get("type", ""):
        process_file_observable(observable)
    else:
        print("Parsing Issue Please research...")
        print(observable)

def handle_indicator(indicator):
    """
    Handle different types of indicators.
    """
    if re.match("mal_url", indicator.Title.text):
        process_url_indicator(indicator)
    elif re.match("mal_domain", indicator.Title.text):
        process_domain_indicator(indicator)
    elif re.match("mal_ip", indicator.Title.text):
        process_ip_indicator(indicator)
    elif re.match("phish_url", indicator.Title.text):
        process_url_indicator(indicator)
    elif re.match("phish_email", indicator.Title.text):
        process_email_indicator(indicator)
    elif re.match("c2_ip", indicator.Title.text):
        process_c2_ip_indicator(indicator)
    elif re.match("c2_url", indicator.Title.text):
        process_c2_url_indicator(indicator)
    elif re.match("phish_domain", indicator.Title.text):
        process_phish_domain_indicator(indicator)
    elif re.match("suspicious_domain", indicator.Title.text):
        process_suspicious_domain_indicator(indicator)
    else:
        print(f'Unparsed Indicator | Name: {indicator.Title.text} | Type: {indicator.Type.text}')

def process_email_observable(observable):
    """
    Process email observable.
    """
    title = observable.Title.text if observable.Title else "ISAC Phishing Email"
    description = observable.Description.text if observable.Description else "ISAC Malicious Email"
    email = observable.Properties.Address_Value.text
    print(f'Title: {title} | Description: {description} | Indicator: {email}')
    cef = f'CEF:0|CE-OSINT|CE-ISAC|1.0|100|ISAC Known Malicious Email|1|suser={email} msg=ISAC Malicious Email {email}'
    send_cef_to_syslog(cef)

def process_ip_observable(observable):
    """
    Process IP observable.
    """
    title = observable.Title.text if observable.Title else "ISAC Malicious IP"
    description = observable.Description.text if observable.Description else "ISAC Malicious IP"
    ip_address = observable.Properties.Address_Value.text
    print(f'Title: {title} | Description: {description} | Indicator: {ip_address}')
    cef = f'CEF:0|CE-OSINT|CE-ISAC|1.0|100|ISAC Known Malicious IP Address|1|request={ip_address} shost={ip_address} msg=ISAC Malicious Domain {ip_address}'
    send_cef_to_syslog(cef)

def process_url_observable(observable):
    """
    Process URL observable.
    """
    title = observable.Title.text if observable.Title else "ISAC Malicious URL"
    description = observable.Description.text if observable.Description else "ISAC Malicious URL"
    url = observable.Properties.Value.text
    print(f'Title: {title} | Description: {description} | Indicator: {url}')
    parsed_url = urlparse(url)
    cef = f'CEF:0|CE-OSINT|CE-ISAC|1.0|100|ISAC Known Malicious Website|1|request={url} shost={parsed_url.netloc} msg=ISAC Malicious Domain {url}'
    send_cef_to_syslog(cef)

def process_file_observable(observable):
    """
    Process file observable.
    """
    title = observable.Title.text if observable.Title else "ISAC Malicious File Hash"
    description = observable.Description.text if observable.Description else "ISAC Malicious File Hash"
    file_hash = observable.Properties.Hash.Simple_Hash_Value.text
    print(f'Title: {title} | Description: {description} | Indicator: {file_hash}')
    cef = f'CEF:0|CE-OSINT|CE-ISAC|1.0|100|ISAC Known Malicious Hash|1|cs1={file_hash} msg=ISAC Malicious File Object: Hash {file_hash}'
    send_cef_to_syslog(cef)

def process_url_indicator(indicator):
    """
    Process URL indicator.
    """
    url_data = indicator.Title.text.split(": ")
    parsed_url = urlparse(url_data[1])
    cef = f'CEF:0|CE-OSINT|CE-ISAC|1.0|100|ISAC Known Malicious Website|1|request={url_data[1]} shost={parsed_url.netloc} msg=ISAC Malicious Domain|URL {url_data[1]}'
    send_cef_to_syslog(cef)

def process_domain_indicator(indicator):
    """
    Process domain indicator.
    """
    domain_data = indicator.Title.text.split(": ")
    parsed_domain = urlparse(domain_data[1])
    cef = f'CEF:0|CE-OSINT|CE-ISAC|1.0|100|ISAC Known Malicious Website|1|request={domain_data[1]} shost={parsed_domain.netloc} msg=ISAC Malicious Domain {domain_data[1]}'
    send_cef_to_syslog(cef)

def process_ip_indicator(indicator):
    """
    Process IP indicator.
    """
    ip_data = indicator.Title.text.split(": ")
    cef = f'CEF:0|CE-OSINT|CE-ISAC|1.0|100|ISAC Known Malicious Host|1|src={ip_data[1]} msg=ISAC Malicious IP {ip_data[1]}'
    send_cef_to_syslog(cef)

def process_email_indicator(indicator):
    """
    Process email indicator.
    """
    email_data = indicator.Title.text.split(": ")
    cef = f'CEF:0|CE-OSINT|CE-ISAC|1.0|100|ISAC Known Malicious Email|1|suser={email_data[1]} msg=ISAC Malicious Email {email_data[1]}'
    send_cef_to_syslog(cef)

def process_c2_ip_indicator(indicator):
    """
    Process C2 IP indicator.
    """
    c2_data = indicator.Title.text.split(": ")
    cef = f'CEF:0|CE-OSINT|CE-ISAC|1.0|100|ISAC Known Malicious C2 Host|1|src={c2_data[1]} msg=ISAC Malicious C2 IP {c2_data[1]}'
    send_cef_to_syslog(cef)

def process_c2_url_indicator(indicator):
    """
    Process C2 URL indicator.
    """
    c2_url_data = indicator.Title.text.split(": ")
    parsed_url = urlparse(c2_url_data[1])
    cef = f'CEF:0|CE-OSINT|CE-ISAC|1.0|100|ISAC Known Malicious C2 Website|1|request={c2_url_data[1]} shost={parsed_url.netloc} msg=ISAC Malicious C2 Domain|URL {c2_url_data[1]}'
    send_cef_to_syslog(cef)

def process_phish_domain_indicator(indicator):
    """
    Process phishing domain indicator.
    """
    phish_domain_data = indicator.Title.text.split(": ")
    parsed_domain = urlparse(phish_domain_data[1])
    cef = f'CEF:0|CE-OSINT|CE-ISAC|1.0|100|ISAC Known Malicious Phishing Website|1|request={phish_domain_data[1]} shost={parsed_domain.netloc} msg=ISAC Phishing Domain {phish_domain_data[1]}'
    send_cef_to_syslog(cef)

def process_suspicious_domain_indicator(indicator):
    """
    Process suspicious domain indicator.
    """
    susp_domain_data = indicator.Title.text.split(": ")
    parsed_domain = urlparse(susp_domain_data[1])
    cef = f'CEF:0|CE-OSINT|CE-ISAC|1.0|100|ISAC Known Malicious Suspicious Website|1|request={susp_domain_data[1]} shost={parsed_domain.netloc} msg=ISAC Suspicious Domain {susp_domain_data[1]}'
    send_cef_to_syslog(cef)

def send_cef_to_syslog(cef_message):
    """
    Send CEF message to syslog.
    """
    print(f'CEF message sent to ArcSight: {cef_message}')
    syslog_host = CONFIG['DESTINATION_IP']['ip']
    syslog_port = int(CONFIG['DESTINATION_IP']['port'])
    send_syslog(cef_message, host=syslog_host, port=syslog_port)

def main():
    """
    Main execution flow.
    """
    date_n_hours_ago = datetime.now() - timedelta(hours=48)
    date_now = datetime.now()

    args_sts = date_n_hours_ago.strftime("%Y-%m-%d %H:%M:%S")
    args_ets = date_now.strftime("%Y-%m-%d %H:%M:%S")

    struct_time = time.strptime(args_sts, '%Y-%m-%d %H:%M:%S')
    begin_ts = datetime(*struct_time[:7]).replace(tzinfo=pytz.UTC)

    e_time = time.strptime(args_ets, '%Y-%m-%d %H:%M:%S')
    end_ts = datetime(*e_time[:7]).replace(tzinfo=pytz.UTC)

    poll_req_xml = create_poll_request(begin_ts, end_ts)

    headers = {
        'Content-Type': 'application/xml',
        'User-Agent': 'TAXII Client Application',
        'Accept': 'application/xml',
        'X-TAXII-Accept': 'urn:taxii.mitre.org:message:xml:1.1',
        'X-TAXII-Content-Type': 'urn:taxii.mitre.org:message:xml:1.1',
        'X-TAXII-Protocol': 'urn:taxii.mitre.org:protocol:https:1.0'
    }

    taxii_url = os.getenv("TAXII_URL", "")
    taxii_user = os.getenv("TAXII_USER", "")
    taxii_password = os.getenv("TAXII_PASSWORD", "")

    response = requests.post(taxii_url, proxies=PROXY_DICT, verify=False, headers=headers, data=poll_req_xml, auth=(taxii_user, taxii_password))

    soup = BeautifulSoup(response.text, "xml")

    print(f'Time Range Start: {args_sts} | Time Range End: {args_ets}')
    parse_observables(soup)
    parse_indicators(soup)

    print("All Done")
    sys.exit(0)

if __name__ == "__main__":
    main()
