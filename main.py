import psutil
import os
import signal
from static import static
import json
import re

from otx import Otx

def runningProcessesInfo():
        processList = []  
        for p in psutil.process_iter():
            processList.append('{} {} {} {}'.format(p.pid, p.name(), p.exe(), static().checkmd5Hash(p.exe())))
        return processList

def killProcess(pid):
    os.kill(pid, signal.SIGTERM)
    print('{} has been killed', pid)

def deleteFile(path):
    if os.path.exists(path):
        os.remove(path)
    else:
        print('File does not exist.')

#Extracts the hash value from runningProcessesInfo() enteries.
def extractHash(string):
    return (re.findall("'([^']*)'", string))

def extractFileLocation(string):
    splitString = string.split()
    return splitString[2]

def extractFileName(string):
    splitString = string.split()
    return splitString[1]

def extractPID(string):
    splitString = string.split()
    return splitString[0]

def writeToJson(location, jsonObject):
    with open(location, 'r') as json_file:
        diction = json.load(json_file)
        diction.append(jsonObject)
        diction = json.dumps(diction)
    with open(location, 'w') as json_file:
        json_file.write('\n' + diction)

def checkJSONFileForPrevScans(location, md5Hash):
    with open(location) as json_file:
        dict = json.load(json_file)
    if any(md5Hash in word for word in dict):
        print(f'{md5Hash} already scanned: safe')
        return True
    else:
        return False

otx = Otx()
while True:
    list = runningProcessesInfo()
    for x in range(len(list)):
        hashlist = extractHash(list[x])
        if checkJSONFileForPrevScans('json/safeprograms.json', hashlist[0]) == True:
            continue
        else:
            pass
        malwareType = otx.file(hashlist[0])
        if malwareType == []:
            name = extractFileName(list[x])
            location = extractFileLocation(list[x])
            jsonData = json.dumps({"name": name, "location" : location, "md5" : hashlist[0], "malware?" : 'no'})
            writeToJson('json/safeprograms.json', jsonData)
        else:
            name = extractFileName(list[x])
            location = extractFileLocation(list[x])
            jsonData = json.dumps({"name": name, "location" : location, "md5" : hashlist[0], "malware?" : malwareType})
            killProcess(extractPID(list[x]))
            deleteFile(location)
            writeToJson('json/malicousprograms.json', jsonData)





