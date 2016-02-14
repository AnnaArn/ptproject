import time
import socket
import struct
import select
import multiprocessing
import sys
import getopt
import fcntl

# Sends a magic and receives the repies

__all__ = ['create_packet', 'send_one']

MAGIC_ID = 1137

def create_packet(source, dest):
    # Prepare ip header fields
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 0  # kernel will fill the correct total length
    ip_id = MAGIC_ID   # set the magic field
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_UDP # socket.IPPROTO_UDP so to be able to recv on the same socket
    ip_check = 0    # kernel will fill the correct checksum
    ip_saddr = socket.inet_aton(source)
    ip_daddr = socket.inet_aton (dest)    
    ip_ihl_ver = (ip_ver << 4) + ip_ihl
    # In network order
    ip_header = struct.pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
    
    # Prepare udp header fields    
    udp_src = 65500   #  It should not matter at all
    udp_dest = 65501  #  It should not matter at all
   
    #  Get the CPU count
    cpu_count= multiprocessing.cpu_count()
   
    cpu_count_packed = struct.pack('!q', cpu_count) #long long
    #user_data = str(cpu_count)
        
    udp_len = 8 + 8 # 8 is the length of the UDP header
    
    #Source port, Destination port, Length, Checksum
    udp_header = struct.pack("!4H", udp_src, udp_dest, udp_len, 0) 

    # final full packet 
    packet = ip_header + udp_header 

    return packet + cpu_count_packed

def send_one(src, dest, timeout=1):
   
    try:
	# Now this is specific -Linux will set by default IP_HDRINC on - we need to supply own IP header.
	# For other you need to set it, if you want to hand-craft you own IP header.
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) #  
	# Include IP headers
	my_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
       
	my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

	# We need to create a reader socket - more specific that SOCK_RAW
	# ETH_P_IP      = 0x0800 # IP only
	my_rsocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)); # 
	
    except socket.error, msg:
	print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
	sys.exit()

    
    packet = create_packet(src, dest)
    
    while packet:
        # Write a broadcast message with cores numbers as a data
        sent = my_socket.sendto(packet, (dest, 0))       
        packet = packet[sent:]
      
    # Receive the responses
    delay = receive_data(my_rsocket, timeout)
  
    # Close the socket
    my_socket.close()
    my_rsocket.close()
	
    return
  
def receive_data(my_socket, timeout):
    # Receive magic data from the socket.
    count = 0
    while True:
	# Timeout is only for inactivity of the select, we could be here for a long time if we have something to process.
	# It could be much better if we track the time we spent in select
        ready = select.select([my_socket], [], [], timeout) 
                
        if ready[0] == []: # Timeout
            return
	
	# We have received something
	recv_packet= my_socket.recvfrom(1024)
	recv_packet = recv_packet[0] # only the string
	
	# We are intrested in IP headers, as we need to check for the MAGIC
	ip_header = recv_packet[14:34] # Grab the IP header
	
	#Unpack the ip header
	ip = struct.unpack('!BBHHHBBH4s4s', ip_header)
	s_addr = socket.inet_ntoa(ip[8]);
        d_addr = socket.inet_ntoa(ip[9]);
 
	ttl = ip[5]
	protocol = ip[6]

	# Only peak into the IPv4 header to see the magic
	ip_id = ip[3]
	
	if ip_id != MAGIC_ID:  #It is not for us
	    #print "Invalid magic: %d " % (ip_id)
            continue
      
	count+=1 # It seems that this is for us
 	
        rec_packet_data = recv_packet[42:50] # Grab the 8B data - as packed long long
        thread_id = struct.unpack('!Q' , rec_packet_data)
        print '	%d: Response received: from %s . Thread id %lu' % (count, str(s_addr), thread_id[0])

def usage():
    print 'rawsender.py -i <ifname> '
    sys.exit()

def get_ip_address(ifname):
    SIOCGIFADDR = 0x8915
    
    try:

      s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      
      r = fcntl.ioctl(s.fileno(), SIOCGIFADDR, struct.pack('256s', ifname[:15]))		    
      ip_addr = socket.inet_ntoa(r[20:24])
    except:
  	print 'Erro, invalid inteface name'
	sys.exit()

    s.close()
    
    return ip_addr


def main(argv):
    try:
	opts, args = getopt.getopt(argv,"hi:",["ifname="])
    except getopt.GetoptError:
	usage()
    for opt, arg in opts:
	if opt == '-h':
	  print 'rawsender.py -i <if_name>'
	  sys.exit()
	elif opt in ("-i", "--ifname"):
	  ifname = arg
    
  
    # Create a packet
    source = get_ip_address(ifname)
    dest = '255.255.255.255' #INADDR_BROADCAST
  
    print "Start sending one package."
    send_one(source, dest, 2)  
if __name__ == '__main__':
  
    # Read interface, you want to send magic packates from the input.
    if len(sys.argv) < 2:
	usage()
    main(sys.argv[1:])
    
 