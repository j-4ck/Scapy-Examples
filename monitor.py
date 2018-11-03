'''
THIS IS AN EXAMPLE OF MONITORING PACKETS AND HANDLING DATA WITH SCAPY
'''

# IMPORT SCAPY MODULE
from scapy.all import *


# make our function that will handle the packets

def Handler(pkt):
	# BELOW ARE EXAMPLES OF DIFFERENT PIECES OF DATA YOU COULD EXAMINE
	# pkt.payload IS JUST THE LAYERS UNDERNEATH OUR FIRST PACKET LAYER
	sourceIP = pkt.payload.src
	# pkt.src WILL SHOW THE SOURCE DATA FOR THE FIRST LAYER. pkt.payload.src WILL SHOW THE SOURCE DATA FOR THE SECOND LAYER (WHICH IS THE DATA WE WANT)
	destinationIP = pkt.payload.dst
	sourcePort = pkt.sport
	destinationPort = pkt.dport
	ttl = pkt.ttl
	# 'TCP' COULD BE CHANGED TO WHATEVER PACKET TYPE YOU WANT (E.G. UDP, ICMP ETC)
	if pkt.haslayer(TCP):
		print '[TCP][TTL:'+str(ttl)+ '] ' + sourceIP+':' + str(sourcePort) + ' -> ' + destinationIP + ':' + str(destinationPort)
		# YOU CAN PLAY AROUND HERE, FOR EXAMPLE:
		if destinationIP == '127.0.0.1':
			print ''
			# DO WHAT YOU WANT, EXPERIMENT

# START SNIFFING, AND FEED PACKETS INTO 'Handler'
sniff(prn=Handler)
print '\nexample end message'
# ANYTHING TO BE EXECUTED AFTER ^C (EXIT MESSAGES ETC) GOES AFTER THE sniff FUNCTION
# NOTE THAT YOU CAN SET A FILTER HERE. FOR EXAMPLE:
#	sniff(prn=Handler, filter = 'tcp port 80')
