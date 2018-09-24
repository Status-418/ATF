import json
from libs import general, virustotal, phishtank, urlquery

general = general.Genreal()
vt = virustotal.Virustotal()
pt = phishtank.PhishTank()
uq = urlquery.Urlquery()

def short_urls(event):
    data = dict()
    data['comments'] = list()
    data['short_url'] = event

    #   Checking if the URL was shortened and if it is expand it
    data['expanded'] = general.expand_url(event)
    if data['expanded']['shortened']:
        data['long_url'] = data['expanded']['long_url']
        data['comments'].append('url was shortened')
        if data['long_url']:
            data['virustotal'] = vt.lookup_url(data['long_url'])
    else:
        data['virustotal'] = vt.lookup_url(event)


    #   checking Phishtank if the url is known to the service
    try:
        data['phishtank'] = dict()

        pt_results = pt.check(event)
        if pt_results.in_database:
            data['phishtank']['malicious'] = True
            data['phishtank']['details'] = pt_results.phish_detail_page
            pt_results
        else:
            data['phishtank']['malicious'] = False
    except:
        data['phishtank']['malicisou'] = False
        data['phishtank']['message'] = 'Failed to query the API'


    #   Determine if the url is know to URLQuery
    if data['expanded']['shortened']:
        data['urlquery'] = uq.check_url(data['long_url'])
        if data['urlquery']['malicious']:
            data['comments'].append('Urlquery found the site to be malicious')
    else:
        data['urlquery'] = uq.check_url(event)
        if data['urlquery']['malicious']:
            data['comments'].append('Urlquery found the site to be malicious')


    #   Check the Whois record of the domain and perform some basic checks

    # Determine if the url was malicious and determine what action to take next
    if data['phishtank'] or data['virustotal']['malicious']:
        data['comments'].append('malicious site')
    if data['virustotal']['malicious'] == 'potentially':
        data['comments'].append('vt found the site to be potentially malicious')


    return data

