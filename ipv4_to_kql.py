"""
    Created by Jose Carlo Husmillo
"""

filename = 'list_ip.txt'

with open(filename) as file_handler:
    ip_list = [line.rstrip() for line in file_handler]

ip_joined = '", "'.join(ip_list)
ip_joined = '"' + ip_joined + '"'

KQL = "DeviceNetworkEvents\n| where Timestamp >= ago(30d)\n| where RemoteIP has_any (" + ip_joined + ")\n"
KQL = KQL + "| project Timestamp, DeviceName, RemoteIP, ActionType, RemotePort, RemoteUrl, LocalIP, LocalIPType, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath\n"

print("KQL is: ")
print(KQL)
