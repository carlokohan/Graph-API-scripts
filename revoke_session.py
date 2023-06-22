import requests
import json
import traceback

from requests.packages.urllib3.exceptions import InsecureRequestWarning

#########

login_url = 'https://login.microsoftonline.com/'
resource = 'https://graph.microsoft.com/'


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


if __name__ == "__main__":

    try:
        client_id = 'xxx'
        client_secret = 'xxx'
        tenant_domain = 'xxx'

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

# https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions?view=graph-rest-1.0&tabs=http

        # get object id
        object_id = 'test@email.com'
        request_url = resource + 'v1.0/users/' + object_id + '/revokeSignInSessions'

        response = requests.post(request_url, headers=header_params)
        print(response.json())

        if response.status_code == 200:
            print("Done revoking session")
        else:
            print("Failed revoking session")

    except Exception:
        print("Error occured.")
        print(traceback.format_exc())
