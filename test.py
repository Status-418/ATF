import requests
import json
import pprint

pp = pprint.PrettyPrinter(indent=4)
URL = 'http://localhost:5000/v1/alerts/raw'

data = dict()
data['alert'] = 'PH Short Urls'
data['data'] = 'https://is.gd/ob8vtI?v=v8.0'

results = requests.post(URL, json=data)

pp.pprint(results.json())