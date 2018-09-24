import json
from alerts import phishing
from flask import Flask, request

app = Flask(__name__)

@app.route('/v1/alerts/raw', methods=['POST'])
def create_alert():
    event = request.get_json()

    if event['alert'] == 'PH Short Urls':
        print(event['data'])
        return json.dumps(phishing.short_urls(event['data']))

    else:
        return "{'status': '500', 'message': 'Please check the data provided'}"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)