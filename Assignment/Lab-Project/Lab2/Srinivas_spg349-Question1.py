#######################################################################################
#
#        Filename : Srinivas(spg349)-Question1.py 
#        Author   : Srinivas
#        Reference: www.secdev.org/projects/scapy/doc
#
#  Summary: This program generates a set of packets for the Input IP given for all the 
#           Ips of its subnet neglecting the Network and Broadcast Address
#
#
#########################################################################################

# Import Modules

import sys                  # System Calls Library
from scapy.all import *     # Scapy Library - Packet Generation and Receiving
import re                   # Re - Regular Expression Library - To Handle Inputs
from netaddr import *       # Netaddr Library - Performing and Analyzing Subnetting

# Obtaining Input from the User
i = raw_input("Enter the Ipaddress: ")

# Validating the Input for the right format
ext = re.search("(.*)/(.*)",i)
if ext:
 ip = ext.group(1)
 mask = ext.group(2) 
else:   
 print "Enter the correct format of IpAddress and Netmaske : IP/Mask"
 sys.exit()

# Using NetAddr Library to verify the Network and Broadcast Address of the subnet
ix = IPNetwork(i)
# Skip for Input being the Broadcast or Network Address
if ip.strip() == str(ix.broadcast) or ip.strip() == str(ix.network):
 print "The IP Entered is broadcast/Network for the subnet ! Exiting !\n"
 sys.exit()
else:
 print "The Network address of the subent   : %s " % (ix.network)
 print "The Subnet Mask of the Network is   : %s" % (ix.netmask)
 print "The Broadcast address of the subnet : %s" % (ix.broadcast) 

# Using Scapy to generate the set of packets in the subnet
count = 0
L3_set = IP(dst=i)               # Layer 3 Setting of Scapy Packet (Destination = input ip)
L4_set = TCP(dport=[80,53])      # Layer 4 Setting the Port numbers given in the question
# Generating the Packets 
print "The Packet Set of the Subnet for the ports is as follows:..."
for packets in L3_set/L4_set: 
    if packets.dst == str(ix.broadcast) or packets.dst == str(ix.network):
       count = count + 1
    else:
       print packets.summary()
#END
