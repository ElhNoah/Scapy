from scapy.all import *

conf.verb=0

#ARP
def arp_request(x):
    ans = sr1(ARP(pdst=x))
    print(ans.show())

#DHCP
def dhcp_discover_request(x):
    scapy.all.conf.checkIPaddr = False
    ans1=srp1(Ether(src=x, dst='ff:ff:ff:ff:ff:ff')/IP(src='0.0.0.0', dst='255.255.255.255')/UDP(dport=67, sport=68)/BOOTP(chaddr=x)/DHCP(options=[('message-type', 'discover'), ('end')]))
    print(ans1.show())
    ans2=srp1(Ether(src=x, dst="ff:ff:ff:ff:ff:ff")/IP(src='0.0.0.0', dst="255.255.255.255")/UDP(dport=67, sport=68)/BOOTP(chaddr=x)/DHCP(options=[("message-type","request"),("server_id",ans1[BOOTP].siaddr),("requested_addr",ans1[BOOTP].yiaddr),"end"]))
    print(ans2.show())

#DNS
def dns_query(x):
    ans = sr1(IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname=x)))
    print(ans.show())
    
#HTTP
def file_request(x):
    load_layer("http")
    req = HTTP()/HTTPRequest(Method=b'GET', Path=b'/', Http_Version=b'HTTP/1.1', Host=x)
    a = TCP_client.tcplink(HTTP, x, 80)
    ans = a.sr1(req)
    a.close()
    print(ans.show())

#ICMP
def ping(x):
    ans = sr1(IP(dst=x)/ICMP())
    print(ans.show())
