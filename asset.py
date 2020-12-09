import socket
import dns.resolver
import ipaddress
import sys
import requests
import json
import re
import os


socketIPList = []
arecordIPList = []
aliveDomainList = []

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


def checkDomain(host):

    try:
        socket.gethostbyname(host)
        return host
    except:
        pass

def getSocketIP(host):

    try:
        ip = socket.gethostbyname(host)
        return ip
    except:
        pass


def getArecordIP(domain_name):

    address = []
    try:
        host_a = dns.resolver.query(domain_name, 'A')
        for i in host_a.response.answer:
            for j in i.items:
                address.append(j.address)
        return address
    except:
        pass


def getIPFromFile(file):

    global socketIPList, arecordIPList, aliveDomainList

    with open(file) as f:
        lines = f.readlines()
        for line in lines:
            line = line.strip()
            aliveDomainList.append(checkDomain(line))
            socketIPList.append(getSocketIP(line))
            arecordIPList.append(getArecordIP(line))

    aliveDomainList = [i for i in aliveDomainList if i]
    socketIPList = [i for i in socketIPList if i]
    arecordIPList = [i[0] for i in arecordIPList if i]

    result = set(socketIPList + arecordIPList)

    return list(result)


def getIP(domains):

    global socketIPList, arecordIPList, aliveDomainList

    for line in domains:
        # line = line.strip()
        aliveDomainList.append(checkDomain(line))
        socketIPList.append(getSocketIP(line))
        arecordIPList.append(getArecordIP(line))

    aliveDomainList = [i for i in aliveDomainList if i]
    socketIPList = [i for i in socketIPList if i]
    arecordIPList = [i[0] for i in arecordIPList if i]

    result = set(socketIPList + arecordIPList)

    return list(result)


def ipsort(IPs):

    sortedIPs = sorted(IPs, key=ipaddress.IPv4Address)

    return sortedIPs


def getCidr(ip):

    res = ''
    ip = ip.split('.')
    ip.pop()
    for x in ip:
        res = res + x + '.'
    res = res.strip('.')

    return res


def getAsset(iplist):

    result = []
    cidr = []

    for ip in iplist:
        result.append(getCidr(ip))

    result = {i: result.count(i) for i in result}

    for key in result:
        if result[key] > 1:
            cidr.append(key + '.0/24')

    return cidr


if __name__ == "__main__":

    domain = sys.argv[1]
    domains = list(set(crtQuery(domain) + vtSubDomainsQuery(domain)))

    aliveIP = getIP(domains)
    aliveAsset = getAsset(aliveIP)

    aliveDomainMsg = '[*] 可用域名: ' + str(len(aliveDomainList)), aliveDomainList
    aliveIPMsg = '[*] 可用IP: ' + str(len(aliveIP)), aliveIP
    aliveAssetMsg = '[*] 资产段: ' + str(len(aliveAsset)), aliveAsset

    for x in aliveDomainMsg:
        print(x)
    print()

    for x in aliveIPMsg:
        print(x)
    print()

    for x in aliveAssetMsg:
        print(x)

    fileName = sys.argv[1] + '.log'

    if os.path.exists(fileName):
        os.remove(fileName)

    with open(fileName, 'a+') as f:
        f.write('\n'.join('%s' % x for x in aliveDomainMsg))
        f.write('\n\n')
        f.write('\n'.join('%s' % x for x in aliveIPMsg))
        f.write('\n\n')
        f.write('\n'.join('%s' % x for x in aliveAssetMsg))

