import socket
import dns.resolver
import ipaddress
import sys


socketIPList = []
arecordIPList = []
aliveDomainList = []


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


def getIP(file):

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

    fileName = sys.argv[1]
    aliveIP = getIP(fileName)
    aliveAsset = getAsset(aliveIP)
    print()
    print('[*] 可用域名: ' + str(len(aliveDomainList)) + '\n', aliveDomainList, '\n')
    print('[*] 可用IP: ' + str(len(aliveIP)) + '\n', aliveIP, '\n')
    print('[*] 资产段: ' + str(len(aliveAsset)) + '\n', aliveAsset)
