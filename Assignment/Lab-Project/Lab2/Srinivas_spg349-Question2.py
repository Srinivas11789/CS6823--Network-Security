#######################################################################################
#
#        Filename : Srinivas(spg349)-Question2.py 
#        Author   : Srinivas
#        Reference: www.secdev.org/projects/scapy/doc
#
#  Summary: This program constructs and sends an ICMP Packets to the target and gets the 
#           response to display
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

# Validating the Input to be in the format IP/Mask
ext = re.search("(.*)/(.*)",i)
if ext:
 ip = ext.group(1)
 mask = ext.group(2) 
else:   
 print "Enter the correct format of IpAddress and Netmaske : IP/Mask\n"
 sys.exit()

# Using Netaddr Library to spot the network and broadcast address of the subnet 
ix = IPNetwork(i)
if ip.strip() == str(ix.broadcast) or ip.strip() == str(ix.network):
 print "The IP Entered is broadcast/Network for the subnet ! Exiting !\n"
 sys.exit()
else: 
 print "You have entered IP of network: %s and netmask: %s" % (ix.network,ix.netmask)

# ICMP Packet Handles
# Contructing ICMP Packet to Send

#print "===> An ICMP Request Packet Paramaters are...."
#ls(ICMP)
# Constructing the ICMP Packet with the destination IP Layer

# Constructing the ICMP Packet with the Dentination IP Layer and ICMP Type Request
print "The Entered IP is %s - Performing ICMP Request..." % (ip)
icmp_req = IP(dst = ip)/ICMP(type = "echo-request")
print "-------> The ICMP Request look like this....."
print icmp_req.summary()
print icmp_req.show()

# Scapy Sender/Receiver Call to obtain the Answer for the request made
icmp_res = sr1(icmp_req,verbose=0)
print "-------> The ICMP Response look like this....."
print icmp_res.summary()
print icmp_res.show()
