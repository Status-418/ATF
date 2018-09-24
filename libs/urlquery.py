import json
import os
import requests
import time

class Urlquery:
    def __init__(self):
        self.uq_key = os.environ['apikey_uq']


    def check_url(self, url):
        data = dict()

        submit = self.scan(url)
        response = self.result(submit['uuid'])
        print(response)


        if response['data']['requests'][0]['response']['response']['status'] == 200:
            if response['stats']['malicious'] == 1:
                data['malicious'] = True
                data['screenshot'] = response['task']['screenshotURL']
                data['report'] = response['task']['reportURL']
            else:
                data['malicious'] = False
                data['screenshot'] = response['task']['screenshotURL']
                data['report'] = response['task']['reportURL']
        else:
            data['malicious'] = False
            data['message'] = 'Failed to retrieve report'
            data['screenshot'] = response['task']['screenshotURL']
            data['report'] = response['task']['reportURL']

        return data

    def scan(self, url):
        uq_url = 'https://urlscan.io/api/v1/scan/'
        headers = {
            'Content-Type': 'application/json',
            'API-Key': self.uq_key,
        }

        data = dict()
        data['url'] = url
        data['public'] = 'on'

        response = requests.post(uq_url, headers=headers, data=json.dumps(data))
        return response.json()

    def result(self, uuid):
        results_url = 'https://urlscan.io/api/v1/result/{}/'.format(uuid)

        while True:
            answer = requests.get(results_url)
            time.sleep(3)
            if answer.status_code == 200:
                break

        return answer.json()

