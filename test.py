import requests
import json
import pprint

pp = pprint.PrettyPrinter(indent=4)
URL = 'http://localhost:5000/v1/alerts/raw'

data = dict()
data['alert'] = 'PH Short Urls'
data['data'] = 'http://ow.ly/aiFs30lW4w1'

results = requests.post(URL, json=data)

pp.pprint(results.json())