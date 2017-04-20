####################################################################################################
#
#                                Lab4 - TCP Port Scanning Using Scapy
#
# Author    : Srinivas Piskala Ganesh Babu (spg349)
# References: www.secdev.org/projects/scapy
#
# Goal : Perform TCP Port Scan and Retrieve the Results to be Open or Closed or Fil 
#
# Solution :
# * Performed a Half way TCP Connection to port scan 
# * If there is no response, Resend Accomplished with Retry Argument as well as with manual handle
# * Analysed the results to be:
#               - None           - Filtered
#               - TCP Response
#                  - SYN/ACK      - Open
#                  - RST/ACK      - Closed
#               - ICMP Response  - Filtered
#
####################################################################################################
# Headers
import sys
from scapy.all import *

# Input Parameters

dst_ip = "10.10.111.1" # IP of the External Router (As Mentioned in the Question)

# Output Parameters - List to present the Output in various category sorted form

Filtered = []
Open = []
Closed = []

# Iterating for Destination Ports 1->100 as mentioned in the quesiton
for i in range(1,101):
# Scapy TCP SYN Packet Builder - IP Layer and TCP Layer
 packet = IP(dst = dst_ip)/TCP(dport= i, flags = "S")
# Send/Receive handle - sr1 - Fetch Only Answer with increased timeout (5 Sec) and Verbose level 0 and Retry 2 times for Lost packet
 tcp_scan = sr1(packet, verbose=0,retry=2, timeout=5) # Increased timeout and retry to compensate network congestion is any
 
# Second packet Construction and Send
 if(str(type(tcp_scan)) == "<type 'NoneType'>"):
   tcp_scan = sr1(packet, verbose=0,timeout=5)
 
# Sorting the Output to Filtered or Open or Closed List based ont he received packet
# Response Validation
 if(str(type(tcp_scan)) == "<type 'NoneType'>"):
   # No Response
   Filtered.append(i)
 elif(tcp_scan.haslayer(TCP)):
   # SYN-ACK
   if(str(tcp_scan["TCP"].flags) == "18" ):
     Open.append(i)
   # RST-ACK
   elif(str(tcp_scan["TCP"].flags) == "20"):
     Closed.append(i)
   # ICMP
 elif(tcp_scan.hashlayer(ICMP)):
   Filtered.append(i)  
 else:
   print "Unknown Received !"

# Output Print
print "The TCP Scan Results are : ----------------- >\n"
print "Host: 10.10.111.1 - External Router"
print "Filtered: ",Filtered
print "Open: ", Open
print "Closed: ",Closed


