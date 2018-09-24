import os

class whois:
    def __init__(self):
        self.whois_key = os.environ['whois_key']
        self.whois_pass = os.environ['whois_pass']

    def get_whois(self, hash):
        print(hash)

