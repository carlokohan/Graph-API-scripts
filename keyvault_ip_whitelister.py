from datetime import date
from dateutil.relativedelta import relativedelta, MO
from subprocess import PIPE, run

import json
import requests
import subprocess
import traceback

constant_ip_list = ["x/32", "x/32", "x/32"]

def send_email(error_str):
    print("Sending email...\n")
    print(error_str)

def download_ip_list():
    relative_week = -1
    url = 'https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_'
    today = date.today()
    last_monday = today + relativedelta(weekday=MO(relative_week))
    formatted_date = last_monday.strftime('%Y%m%d')

    complete_url = url + formatted_date + ".json"
    response = requests.get(complete_url)
    # loop to the previous weeks until we find the monday that has the json file
    while(response.status_code >= 300):
        relative_week = relative_week - 1
        last_monday = today + relativedelta(weekday=MO(relative_week))
        formatted_date = last_monday.strftime('%Y%m%d')
        complete_url = url + formatted_date + ".json"
        response = requests.get(complete_url)

        if relative_week <= -52:
            raise Exception("Something's wrong, reached -52 relative weeks. Check download url...")

    return response.json()

def get_devops_ips(azure_ips):
    values = azure_ips['values']
    for item in values:
        if item['name'] == 'AzureDevOps':
            properties = item['properties']
            return properties['addressPrefixes']

    raise Exception('Check formatting of JSON file')

def remove_previous_ip():
    command = ['az', 'keyvault', 'network-rule', 'list', '--name', 'x']
    result = run(command, stdout=PIPE, stderr=PIPE, text=True)
    data = json.loads(result.stdout)
    ip_list = data['ipRules']

    for ip in ip_list:
        if ip['value'] not in constant_ip_list:
            command = ['az', 'keyvault', 'network-rule', 'remove', '--resource-group', 'x', '--name', 'x', '--ip-address', ip['value']]
            result = run(command, stdout=PIPE, stderr=PIPE, text=True)

    print("Removed old IP CIDR")

def upload_new_list(azure_latest_devops_ip_list):
    for ip in azure_latest_devops_ip_list:
        command = ['az', 'keyvault', 'network-rule', 'add', '--resource-group', 'x', '--name', 'x', '--ip-address', ip]
        result = run(command, stdout=PIPE, stderr=PIPE, text=True)
        print("Successfully added ip: "+ip)

if __name__ == "__main__":
    print("Starting Azure KeyVault IP whitelister")
    try:
        azure_ips = download_ip_list()
        azure_latest_devops_ip_list = get_devops_ips(azure_ips)
        remove_previous_ip()
        upload_new_list(azure_latest_devops_ip_list)
    except Exception as e:
        send_email(traceback.format_exc())
        print("Error occured.")
