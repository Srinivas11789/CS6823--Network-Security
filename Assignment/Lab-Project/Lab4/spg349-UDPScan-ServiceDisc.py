###################################################################################################
#
#                                 UDP Port Scanning Using Scapy
#
#    Author    : Srinivas Piskala Ganesh Babu
#    References: www.secdev.org/projects/scapy 
#
#    Goal: 
#         * Perform UDP Scan and Retrieve the Results to be Open, Closed or Open|Filtered
#         * Perform Service Discovery for the respective ports
#         * Craft a Packets corresponding to the Service and Send to the Open Port
#
#   Solution:
#         * Performed UDP Scan
#         * Handled Network congestion by managing no response with retry argument and manual handle
#         * Analyzed the Response to be:
#                   - None          - Open or Filtered
#                   - UDP Response  - Open
#                   - ICMP Response - Filtered
#                   - ICMP Response -
#
#        * Handled the Port:Service relationship with a dictionary
#        * Once the Service is discovered, the respective packet is crafted and sent
#                                     - This case DNS and DHCP Packets are handled
# 
#####################################################################################################

# Headers
import sys
from scapy.all import *

# Input Parameters

dst_ip = "10.10.111.1" # IP of the External Router

# Output Parameters - List to present the Output in various category sorted form

Open = []
Closed = []
openORfilter = []

# Iterating for Destination Ports 1->100 as mentioned in the quesiton
for i in range(1,101):
# Scapy UDP SYN Packet Builder - IP Layer and TCP Layer
 packet = IP(dst = dst_ip)/UDP(dport= i)
# Send/Receive handle - sr1 - Fetch Only Answer with increased timeout (5 Sec) and Verbose level 0 and Retry 2 times for Lost packet
 udp_scan = sr1(packet, verbose=0,retry=2, timeout=5)

# Retry Handle to retry manually one time
 if("None" in str(type(udp_scan))):
     udp_scan = sr1(packet, verbose=0, timeout=5)

# Sorting the Output to Filtered or Open or Closed List based ont he received packet
 if("None" in str(type(udp_scan))):
     openORfilter.append(i)
 elif(udp_scan.haslayer(UDP)):
     Open.append(i)
 elif(udp_scan.haslayer(ICMP)):
      if (udp_scan["ICMP"].type == 3 and udp_scan["ICMP"].code == 3):
          Closed.append(i)  
      else:
          openORfilter.append(i)
 else:
   print "Unknown Received !"

# Output Print
print "The UDP Scan Results are : ----------------- >\n"
print "Host: 10.10.111.1 - External Router"
print "Open or Filtered List is: ", openORfilter
print "Open: ", Open
print "Closed: ",Closed

#--------------------> Service Name Discovery

# Service and Port name List - Obtained from IANA 
service_list = {"53":"domain", "67":"dhcps","68":"dhcpc"}
# Response Handle to Record the response of Open Ports
response = []

# Packet Construction
# Packet Crafting for the Open Ports Service Name - 53 67 68
Packet53 = IP(dst= dst_ip)/UDP(dport=53)/DNS(qd=DNSQR(qname="www.google.com"))
# Based on secdev.org documentation - Scapy configuration for check ip to false for the DHCP to work
conf.checkIPaddr = False
# Retrieve the HW Mac of the Interface
fam,hw = get_if_raw_hwaddr(conf.iface)
Packet68 = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=hw)/DHCP(options=[("message-type","discover"),"end"])

# Check for Port Service Existence and Packet Send based on the respective Service
# Output for Port and Service Name
print "-----> The Output with the Service name is:"
print "\nPort\tService"
for port in openORfilter:
    if str(port) in service_list:
       print "%s\t%s" % (str(port),service_list[str(port)])

print "\n---> The Responses of the Packets Received are:\n "

for port in openORfilter:
       if str(port) == "53":
           print "-------------- DNS ------------"
           dns = sr1(Packet53,verbose=0,timeout=2)
           print dns.summary()
           print "\n"
       elif str(port) == "67":
           print "--------------- DHCP ------------"
           dhcp, unans = srp(Packet68,verbose=0,timeout=2)
           dhcp.summary()
       
