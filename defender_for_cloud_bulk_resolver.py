#Export first the security alerts to a CSV file from Defender for Cloud portal, then save it as xlsx. Then change the file name below
import requests
import json
import traceback
import csv
import pandas as pd
import math

from requests.packages.urllib3.exceptions import InsecureRequestWarning

#########

login_url = 'https://login.microsoftonline.com/'
resource = 'https://management.core.windows.net/'


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)



if __name__ == "__main__":
    # read by default 1st sheet of an excel file
    dataframe1 = pd.read_excel('defender_for_cloud_alerts.xlsx')

    #print(dataframe1['subscriptionId'])

    for index, row in dataframe1.iterrows():
        print(row['subscriptionId'], row['resourceGroup'], row['alertId'], row['alertLocation'])
        if str(row['resourceGroup']) == 'nan':
            print("No Resource group")
            continue

        client_id = 'xxx'
        client_secret = 'xxx'
        tenant_domain = 'xxx'

        bodyvals = {'client_id': client_id,
                    'client_secret': client_secret,
                    'grant_type': 'client_credentials',
                    'resource': resource}

        request_url = login_url + tenant_domain + '/oauth2/token'
        token_response = requests.post(request_url, data=bodyvals)
        print(token_response.text)

        access_token = token_response.json().get('access_token')
        token_type = token_response.json().get('token_type')

        final_token = token_type + ' ' + access_token
        header_params = {'Authorization': final_token, 'Content-Type': 'application/json'}
        #print(header_params)
        request_url = 'https://management.azure.com/subscriptions/' + row['subscriptionId'] + '/resourceGroups/' + row['resourceGroup'] + '/providers/Microsoft.Security/locations/' + row['alertLocation'] + '/alerts/' + row['alertId'] + '/resolve?api-version=2022-01-01'

        response = requests.post(request_url, headers=header_params)
        print(response.text)

        if response.status_code == 200 or response.status_code == 204:
            print("Done resolving")
        else:
            print("Failed resolving")
