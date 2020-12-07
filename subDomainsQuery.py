# # subDomainSScan = SDSS
import requests
import json
import re

def crtQuery(host):

    try:
        domainList = []
        r = requests.get(f'https://crt.sh/?q={host}', timeout=10)
        result = r.text
        crt = re.findall('<tr>(?:\s|\S)*?href="\?id=([0-9]+?)"(?:\s|\S)*?<td>([*_a-zA-Z0-9.-]+?\.' + re.escape(host) + ')</td>(?:\s|\S)*?</tr>', result, re.IGNORECASE)
        for cert, domains in crt:
            domain = domains.split('@')[-1]
            domainList.append(domain)
        domainList.append(host)
        return list(set(domainList))

    except:
        pass


# print(crtQuery('dasb.me'))


def vtSubDomainsQuery(host):
    r = requests.get(f'https://www.virustotal.com/vtapi/v2/domain/report?apikey=&domain={host}', timeout=10)
    result = r.text
    domainList = []
    result = json.loads(result)
    if 'subdomains' in result.keys():
        for line in result['subdomains']:
            domainList.append(line)
    domainList.append(host)
    return domainList


if __name__ == "__main__":

    domain = 'dasb.me'
    domains = list(set(crtQuery(domain) + vtSubDomainsQuery(domain)))
    print(domains)
