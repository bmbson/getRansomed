import hashlib, json, requests, os
from otx import Otx

class static:
    def __init__(self):
        try:
            self.readhashdict()
        except:
            self.hashdict = {}
            self.savehashdict()

    
    def checkmd5Hash(self,file):
        BUF_SIZE = 65536  

        md5 = hashlib.md5()
        sha1 = hashlib.sha1()

        with open(file, 'rb') as f:
            while True:
                data = f.read(BUF_SIZE)
                if not data:
                    break
                md5.update(data)
                sha1.update(data)

        return md5.hexdigest(), sha1.hexdigest()

    def savehashdict(self):
        with open("hashdict.json", "w") as f:
            f.write(json.dumps(self.hashdict))

    def readhashdict(self):
        with open("hashdict.json") as f:
            self.hashdict = json.loads(f.read())
    
    def readapidict(self):
        with open("apidict.json") as f:
            self.apidict = json.loads(f.read())
        

    def queryAPIs(self):
        self.readapidict()
        for api in self.apidict:
            base = api["url"]
            headers = {
                "apikey": api["key"]
            }
            apiheaders = headers.update(api.get("headers", {}))
            apibody = api.get("body", {})
            res = requests.get(base, headers=headers, body=apibody)
            data = res.json
