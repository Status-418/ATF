import json
from libs import general, virustotal, phishtank

general = general.Genreal()
vt = virustotal.Virustotal()
pt = phishtank.PhishTank()

def short_urls(event):
    data = dict()
    data['comments'] = list()
    data['short_url'] = event

    #   Checking if the URL was shortened and if it is expand it
    data['expanded'] = general.expand_url(event)
    if data['expanded']['shortened']:
        data['long_url'] = data['expanded']['long_url']
        data['comments'].append('url was shotrened')
        if data['long_url']:
            data['virustotal'] = vt.lookup_url(data['long_url'])
    else:
        data['virustotal'] = vt.lookup_url(event)


    #   checking Phishtank if the url is known to the service
    pt_results = pt.check(event)
    print(pt_results)
    if pt_results.in_database:
        data['phishtank'] = True
    else:
        data['phishtank'] = False

    #   Check the Whois record of the domain and perform some basic checks

    # Determine if the url was malicious and determine what action to take next
    if data['phishtank'] or data['virustotal']['malicious']:
        data['comments'].append('malicious site')
    elif data['virustotal']['malicious'] == 'potentially':
        data['comments'].append('potentially malicious')

    return data

