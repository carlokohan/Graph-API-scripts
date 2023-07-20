# Set the device value to High from list in a file
import requests
import json
import traceback
import time

login_url = 'https://login.microsoftonline.com/'
resource2 = 'https://api-eu.securitycenter.microsoft.com/' #whichever server your nearer

if __name__ == "__main__":

    try:
        client_id = 'xx'
        client_secret = 'xx'
        tenant_domain = 'xx'

        bodyvals = {'client_id': client_id,
                    'client_secret': client_secret,
                    'grant_type': 'client_credentials',
                    'resource': resource2}

        request_url = login_url + tenant_domain + '/oauth2/token'
        token_response = requests.post(request_url, data=bodyvals)

        access_token = token_response.json().get('access_token')
        token_type = token_response.json().get('token_type')

        final_token = token_type + ' ' + access_token
        header_params = {'Authorization': final_token, 'Content-Type': 'application/json'}
        device_value = {'DeviceValue': 'High'}

        with open("devices.txt") as file_in:
            lines = []
            i = 1
            for device_id in file_in:
                if i == 100:
                    i = 1
                    time.sleep(61) # 100 request limit in 1 minute
                stripped = device_id.strip()
                request_url = resource2 + 'api/machines/' + stripped + '/setDeviceValue'
                print(request_url)
                response = requests.post(request_url, headers=header_params, data=json.dumps(device_value))
                if response.status_code > 300:
                    print("Error: " + device_id)
                    print(response.json())
                else:
                    print("updated: " + device_id)

                i = i+1


    except Exception:
        print("Error occured.")
        print(traceback.format_exc())
