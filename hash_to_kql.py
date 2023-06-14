"""
    Created by Jose Carlo Husmillo
"""
import csv

filename = 'data_hash.csv'
md5 = []
sha1 = []
sha256 = []

with open(filename, 'r') as file_handler:
    datareader = csv.reader(file_handler)
    for row in datareader:
        if row[0] == 'md5':
            md5.append(row[1])
        elif row[0] == 'sha1':
            sha1.append(row[1])
        elif row[0] == 'sha256':
            sha256.append(row[1])


KQL = "union DeviceFileEvents, DeviceProcessEvents, DeviceEvents\n| where Timestamp >= ago(30d)\n| where "
if md5:
    md5_joined = '", "'.join(md5)
    KQL = KQL + 'MD5 has_any ("' + md5_joined + '") '
if sha1:
    sha1_joined = '", "'.join(sha1)
    if md5:
        KQL = KQL + 'or SHA1 has_any ("' + sha1_joined + '") '
    else:
        KQL = KQL + 'SHA1 has_any ("' + sha1_joined + '") '
if sha256:
    sha256_joined = '", "'.join(sha256)
    if md5 or sha1:
        KQL = KQL + 'or SHA256 has_any ("' + sha256_joined + '") '
    else:
        KQL = KQL + 'SHA256 has_any ("' + sha256_joined + '") '

KQL = KQL + 'or FileName == "est.exe" or FileName == "xxx.exe" or FileName == "Mim.exe" or FileName == "xxxw.exe" or FileName == "crackmapexec.exe" or FileName == "Services.exe" or FileName == "plink.exe" or FileName == "Systems.exe" or FileName == "PsExec64.exe"'+"\n"
KQL = KQL + '| project Timestamp, DeviceName, AccountUpn, ActionType, FileName, FolderPath, SHA1, SHA256, MD5, InitiatingProcessFileName'


print("KQL is: ")
print(KQL)
