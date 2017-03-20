##########################################################################################
#
#        Filename : Srinivas(spg349)-Question3.py 
#        Author   : Srinivas
#        Reference: www.secdev.org/projects/scapy/doc
#
#  Summary: Part1 :Host and Port Identification
#                  This program performs TCP Traceroute - Constructing a TCP SYN Packet to the
#                  Target with TTL 1 and Waiting for a SYN/ACK "OPEN" or RST/ACK "Closed" 
#                  condition. It Iterates through all the ports of the Target.
#                  If No Response is received - Trigger Retry with TTL increment
#           Part2 : Host Only Identification based on the Number of HOPS
#
#  Assumption: Hop Count-> Assuumed to be max 16 - based on limit of most Routing Protocols
#              Ports    -> Queried to all the reserved ports from 1 -> 1024; Can be altered
#
###########################################################################################

# Import Modules

import sys                  # System Calls Library
from scapy.all import *     # Scapy Library - Packet Generation and Receiving
import re                   # Re - Regular Expression Library - To Handle Inputs
from netaddr import *       # Netaddr Library - Performing and Analyzing Subnetting

# Obtaining Input from the User
i = raw_input("Enter the Ipaddress: ")

# Setting the TTL to 1 to start with One Hop
ttl = 1
# Open and Close Port Numbers
o = 0
c = 0
# Validating the Input IP for the format Ip/Mask
ext = re.search("(.*)/(.*)",i)
if ext:
 ip = ext.group(1)
 mask = ext.group(2) 
else:   
 print "Enter the correct format of IpAddress and Netmaske : IP/Mask\n"
 sys.exit()

# Using Netaddr Library to Verify the Network and Broadcast address of the subnet
ix = IPNetwork(i)
if ip.strip() == str(ix.broadcast) or ip.strip() == str(ix.network):
 print "The IP Entered is broadcast/Network for the subnet ! Exiting !\n"
 sys.exit()
else: 
 print "You have entered IP of network:%s and netmask:%s" % (ix.network,ix.netmask)

# TCP Traceroute Start
print "Performing TCP Traceroute....PORT and HOST Identification...."
print "The Entered IP is %s - Performing TCP Request..." % (ip)
done = 0
# Running Loop for Hop Count to be atleast 16
while(True):
 print "===> Executing with TTL --> %d hops" % (ttl)
 print "Port\t\tStatus\t\tRoundTripTime\tPacket_Generated\n"
# Iterating for all the reserved ports
 for i in range(1,10):
# IP Layer and TCP Layer Construction using SCAPY Library
  tcp_req = IP(dst = ip,ttl = ttl)/TCP(dport = i,flags = "S")
# Scapy Send/Receive Handle
  tcp_res = sr1(tcp_req, verbose=0,timeout=3)
# Checking for TCP Response Else Increasing TTL
  try:
   if tcp_res[1]["TCP"]:
     result = tcp_res[1]["TCP"].flags
# Check for the flags to be SA (SYN/ACK) = 18 or RA (SYN/ACK) = 20
     if str(result) == "18":
        stat = "open"
        o = o + 1
     elif str(result) == "20":
        stat = "closed"
        c = c + 1
     else:
        stat = "Unknown"
# Printing with the Round Trip Time Calculation
     print "%d\t\t%s\t\t%s   %s" % (i,stat,str((tcp_res[1].time-tcp_res[0].time)*1000)[:5],str(tcp_req.summary()))
     done = 1
# Increasing the TTL and Looping over until the TTL exceeds 16 hops
  except:
     try:
# Increasing TTL when ICMP response is received
      if tcp_res.haslayer(ICMP):
        print "Increasing TTL......."
        ttl = ttl + 1
        done = 0
        if ttl > 16:
            print "\nDone...Reached Maximum Hop of 16 ! Host Not reachable !\n"
            sys.exit()
        break
# Handle for NULL Type Received - Possible Scapy Bug Based on Reference
     except:
        print "NoneType Received !"
        sys.exit()
 if done == 1:
    break
# Result Summary
print "\nDone...! Stats are Open: %d and Closed: %d\n" % (o,c)
# Part2 - Host Only Identification
# Get the Host Reahability in number of HOPS
print "====> Host Only Identification:\n"
tcp2 = IP(dst = ip,ttl = (1,16))/TCP(flags = "S")
result = sr(tcp2,verbose=0,timeout=3)
print "TTL     IPAddress   TCP  RTT\tPacket\n"
# Calculation of Round trip time from the source time and receive time
# Used HasLayer to test if a TCP Layer is present in the response
for a,b in result[0]:
    print "%s     %s   %s   %s  %s" % (a.ttl,b.src,str(b.haslayer(TCP)),str((b.time - a.time))[:4],str(b.summary()))



      
 



