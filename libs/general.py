import requests

class Genreal:
    def __init__(self):
        pass

    def expand_url(self, short_url):
        data = dict()
        try:
            session = requests.Session()  # so connections are recycled
            resp = session.head(short_url, allow_redirects=True)
            if not short_url == resp.url:
                data['long_url'] = resp.url
                data['shortened'] = True
            else:
                data['shortened'] = False
                data['message'] = 'URL not shortened'
        except:
            data['shortened'] = False
            data['message'] = 'Failed to retrieve url'
        return data

