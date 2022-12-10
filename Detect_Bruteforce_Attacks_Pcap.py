import dpkt
import sys
import datetime

#filename='new1.pcap'
filename=sys.argv[1]
f = open(filename,'rb')
pcap = dpkt.pcap.Reader(f)
count=0
l=open('result.txt','w')


for timestamp, buf in pcap:

    # Unpack the Ethernet frame (mac src/dst, ethertype)
    eth = dpkt.ethernet.Ethernet(buf)

    # Now grab the data within the Ethernet frame (the IP packet)
    ip = eth.data

    # Check for TCP in the transport layer
    if isinstance(ip.data, dpkt.tcp.TCP):

        # Set the TCP data
        tcp = ip.data

        # Now see if we can parse the contents as a HTTP request
        try:
            request = dpkt.http.Request(tcp.data)
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            continue
        
        # print ('HTTP request: ' ,repr(request.uri))
        temp=(repr(request.uri)).split('?')
        

        if(len(temp)>1 and temp[0]=="'/DVWA/vulnerabilities/brute/index.php"):
            k=temp[1].split('&')
            h='Username: '+(k[0].split('='))[1]+'  Password: '+(k[1].split('='))[1]
            print(h)
            
            l.write(h)
            l.write('\n')
            
            count=count+1

print('\nThe total number of bruteforce attempts: ',count)
l.close()