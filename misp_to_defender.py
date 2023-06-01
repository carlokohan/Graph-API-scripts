"""
    Created by Jose Carlo Husmillo
"""

import requests
import datetime
import logging
import time
import json

from pprint import pprint
from pymisp import PyMISP
from pymisp import MISPEvent
from requests.packages.urllib3.exceptions import InsecureRequestWarning

#########

login_url = 'https://login.microsoftonline.com/'
resource = 'https://api.securitycenter.microsoft.com'

logger = logging.getLogger("hisac-feed-logs")
logger.setLevel(logging.DEBUG)
filehdr = logging.FileHandler('/home/xxx/handler-logs.txt')
filehdr.setLevel(logging.INFO)
logger.addHandler(filehdr)
logger.info("Initialized logger.")

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def get_event_ids():
    file_h = open('/home/xxx/event_ids.txt', 'r')
    events_str = file_h.read()
    return events_str.strip('\n').split(',')

def get_ioc_list(event_ids):
    # template for an ioc
    expiration_1_week = datetime.datetime.now() + datetime.timedelta(days=7)

    ioc = {
        "indicatorValue": "220e7d15b011d7fac48f2bd61114db1022197f7f",
        "indicatorType": "FileSha256",
        "title": "H-ISAC Amber feed",
        "application": "Defender IOC uploader",
        "expirationTime": expiration_1_week.strftime('%Y-%m-%d'),
        "action": "Block",
        "severity": "Informational",
        "description": "H-ISAC Amber feed",
        "recommendedActions": "nothing"
    }
    ioc_list = []

    # The URL pointing to your MISP instance
    misp_url= "https://xxxx.yyy"
    # Your MISP API key
    misp_api = "api_key"
    misp_src = PyMISP(misp_url, misp_api, False, 'json')
    ioc_count = 1

    for event_id in event_ids:
        event = misp_src.get_event(event_id, pythonify=True)

        if ioc_count <= 50:
            for attribute in event.Attribute:
                if attribute.type == 'sha256':
                    ioc['indicatorValue'] = attribute.value
                    # shallow copy the dictionary to change value when storing to list
                    new_ioc = ioc.copy()
                    ioc_count = ioc_count + 1
                    ioc_list.append(new_ioc)
    final_list = {}
    final_list['Indicators'] = ioc_list
    return final_list


if __name__ == "__main__":
    logger.info("Starting HISAC feed IOC forwarder.")
    try:
        client_id = 'app id'
        client_secret = 'secret'
        tenant_domain = 'domain'

        bodyvals = {'client_id': client_id,
                    'client_secret': client_secret,
                    'grant_type': 'client_credentials',
                    'resource': resource}

        request_url = login_url + tenant_domain + '/oauth2/token'
        token_response = requests.post(request_url, data=bodyvals)

        access_token = token_response.json().get('access_token')
        token_type = token_response.json().get('token_type')

        final_token = token_type + ' ' + access_token
        header_params = {'Authorization': final_token, 'Content-Type': 'application/json'}
        
        request_url = resource + '/api/indicators/import'
        event_ids = get_event_ids()
        print(str(event_ids))
        ioc_list = get_ioc_list(event_ids)

        response = requests.post(request_url, headers = header_params, data=json.dumps(ioc_list))
        print(response.json())

        if response.status_code == 200:
            logger.info("Done! SUCCESSFULLY UPLOADED!")
        else:
            logger.info("Failed to post")
    except Exception as e:
        logger.info(str(e))
        logger.info("Error occured.")
