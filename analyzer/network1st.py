from scapy.all import *
import time

packet_count={}

def connectivity():
    # this is to check my phone connectivity
    MyPhone_ip="192.168.1.5"
    send_time=time.time()
    is_it_down= sr1(IP(dst=MyPhone_ip)/ICMP(), timeout=2)
    response_time=time.time()
    if is_it_down:
        rtt=(send_time-response_time)*1000
        print(f"Response from my phone IP: {MyPhone_ip} took {rtt} ms")
    else:
        print("my mobile phone is down TIMEOUT")

def tp():
    dst_ip= "1.1.1.1"
    ping= 10
    sent=0
    received=0
    for i in range(ping):
        sent+=1
        packet_to_send= IP(dst=dst_ip)
        send_time=time.time()
        response=sr1(packet_to_send/ICMP(),timeout=1)
        response_time=time.time()
        if response:
            received+=1
            rtt= (response_time - send_time)*1000
            print(f"Response from {dst_ip} took {rtt} ms")
        else:
            print("Request timed out")

    loss= (sent-received)/sent *100
    print(f"Sent: {sent}, Received: {received}, Packet Loss: {loss:.2f}%")

def packet_check(randompck):
    global packet_count
    allowed_port=443 #as an example we will monitor https port
    allowedIP='62.231.244.98' 
    if randompck.haslayer('TCP') and randompck.haslayer('IP'):
        if randompck['TCP'].dport != allowed_port and randompck['IP'].dst != allowedIP:
            src_ip = randompck['IP'].src
            dstport=randompck['TCP'].dport
            if src_ip not in packet_count:
                packet_count[src_ip]={dstport:1}
            else:
                if dstport not in packet_count[src_ip]:
                    packet_count[src_ip][dstport]=1
                else:
                    packet_count[src_ip][dstport]+=1
    print(packet_count)

#connectivity()
sniff(prn=packet_check, store=False)