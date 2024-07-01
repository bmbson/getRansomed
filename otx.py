from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes

class Otx:
    def __init__(self):
        API_KEY = '3ac8814abe79338ace98e1340d63bac0c73a422070a67557dd79ff31aedb7a8f'
        OTX_SERVER = 'https://otx.alienvault.com/'
        self.otx = OTXv2(API_KEY, server=OTX_SERVER)

    def getValue(self, results, keys):
        if type(keys) is list and len(keys) > 0:

            if type(results) is dict:
                key = keys.pop(0)
                if key in results:
                    return self.getValue(results[key], keys)
                else:
                    return None
            else:
                if type(results) is list and len(results) > 0:
                    return self.getValue(results[0], keys)
                else:
                    return results
        else:
            return results

    def file(self, hash):
        alerts = []

        hash_type = IndicatorTypes.FILE_HASH_MD5
        if len(hash) == 64:
            hash_type = IndicatorTypes.FILE_HASH_SHA256
        if len(hash) == 40:
            hash_type = IndicatorTypes.FILE_HASH_SHA1

        result = self.otx.get_indicator_details_full(hash_type, hash)

        avg = self.getValue( result, ['analysis','analysis','plugins','avg','results','detection'])
        if avg:
            alerts.append({'avg': avg})

        clamav = self.getValue( result, ['analysis','analysis','plugins','clamav','results','detection'])
        if clamav:
            alerts.append({'clamav': clamav})

        avast = self.getValue( result, ['analysis','analysis','plugins','avast','results','detection'])
        if avast:
            alerts.append({'avast': avast})

        microsoft = self.getValue( result, ['analysis','analysis','plugins','cuckoo','result','virustotal','scans','Microsoft','result'])
        if microsoft:
            alerts.append({'microsoft': microsoft})

        symantec = self.getValue( result, ['analysis','analysis','plugins','cuckoo','result','virustotal','scans','Symantec','result'])
        if symantec:
            alerts.append({'symantec': symantec})

        kaspersky = self.getValue( result, ['analysis','analysis','plugins','cuckoo','result','virustotal','scans','Kaspersky','result'])
        if kaspersky:
            alerts.append({'kaspersky': kaspersky})

        suricata = self.getValue( result, ['analysis','analysis','plugins','cuckoo','result','suricata','rules','name'])
        if suricata and 'trojan' in str(suricata).lower():
            alerts.append({'suricata': suricata})

        return alerts