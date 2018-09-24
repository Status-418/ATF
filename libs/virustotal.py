import json
import os
import requests

class Virustotal:

    def __init__(self):
        self.vt_key = os.environ['apikey_vt']
        self.url = 'https://www.virustotal.com/vtapi/v2'
        self.headers = {"Accept-Encoding": "gzip, deflate", "User-Agent": 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36'}
        pass

    def lookup_hash_raw(self, hash):
        vt_url = '{}/file/report'.format(self.url)
        params = {'apikey': self.vt_key, 'resource': hash}

        response = requests.get(vt_url, params=params, headers=self.headers)
        return response.json()


    def lookup_url_raw(self, url):
        vt_url = '{}/url/report'.format(self.url)
        params = {'apikey': self.vt_key, 'resource': url}

        response = requests.post(vt_url, params=params, headers=self.headers)
        return response.json()


    def lookup_url(self, url):
        data = dict()

        raw = self.lookup_url_raw(url)
#        print(json.dumps(raw, indent=4))

        if raw['response_code'] == 1:
            data['score'] = '{}/{}'.format(raw['positives'], raw['total'])
            data['permalink'] = raw['permalink']
            data['scan_date'] = raw['scan_date']
            data['detections'] = list()

            for vendor, results in raw['scans'].items():
                if results['detected']:
                    detection = dict()
                    detection['vendor'] = vendor
                    detection['detected'] = results['detected']
                    detection['result'] = results['result']

                    data['detections'].append(detection)

            if raw['positives'] == 0:
                data['malicious'] = False
            elif raw['positives'] <= 6:
                data['malicious'] = 'potentially'
            else:
                data['malicious'] = True
        else:
            data['malicous'] = False
            data['message'] = raw['verbose_msg']

        return data


    def submit_url(self, url):
        vt_url = '{}/url/scan'.format(self.url)
        params = {'apikey': self.vt_key, 'url': url}

        response = requests.post(vt_url, data=params)
        return response.json()
