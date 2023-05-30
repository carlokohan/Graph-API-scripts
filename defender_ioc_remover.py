"""
    Created by Jose Carlo Husmillo
    Get all indicators on your Defender. Search all of it in Virus Total then deletes it in your Defender if Microsoft already finds it malicious in VT
"""

import requests
import datetime
import time
import json
import traceback

from requests.packages.urllib3.exceptions import InsecureRequestWarning

#########

login_url = 'https://login.microsoftonline.com/'
resource = 'https://api.securitycenter.microsoft.com'

client_id = 'xxx'
client_secret = 'xxx'
tenant_domain = 'xxx'
        
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def delete_ioc(ioc_id):
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

    request_url = resource + '/api/indicators/' + ioc_id

    response = requests.delete(request_url, headers = header_params)
    if response.status_code < 300:
        print("Deleted ioc")
    else:
        print("Error in Deletion")


def cleanup_ioc(ioc_list):
    requests_done = 0
    url = "https://www.virustotal.com/api/v3/files/"
    headers = {"accept": "application/json", "x-apikey": 'xxx'}

    for ioc in ioc_list:
        if ioc['indicatorType'] not in ['IpAddress', 'DomainName', 'Url']:
            q_url = url + ioc['indicatorValue']
            response = requests.get(q_url, headers=headers)
            requests_done = requests_done + 1

            if response.status_code in [404, 400]:
                print('File not yet in VT. error: ' + str(response.status_code))
                continue

            if response.status_code == 200:
                data_json = response.json()
                verdict = data_json['data']['attributes']['last_analysis_results']['Microsoft']['category']

                if verdict == 'malicious':    #'undetected' is the other value
                    print("DELETING ioc: " + ioc['indicatorValue'])
                    delete_ioc(ioc['id'])
            else:
                print("Error: " + response.json())

        if requests_done == 4:
            requests_done = 0
            print("sleeping...")
            time.sleep(61) #VT limit of 4 request per minute


if __name__ == "__main__":
    print("Starting Defender IOC cleaner")
    try:

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

        request_url = resource + '/api/indicators'

        response = requests.get(request_url, headers = header_params)
        data_json = response.json()
        ioc_list = data_json['value']

        if response.status_code == 200:
            print("Got the list")
        else:
            print("Error in getting list")

        cleanup_ioc(ioc_list)
    except Exception as e:
        print(traceback.format_exc())
        print("Error occured.")
