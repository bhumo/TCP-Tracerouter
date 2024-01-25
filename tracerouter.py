import socket
import time
import argparse
from scapy.all import IP, TCP, ICMP, Raw


MAX_HOP = 30


class IP_ADDRESS:
   def __init__(self,ip_addr,rtt):
       self.ip_addr = ip_addr
       self.rtt = [round(rtt,3)]


   # def __hash__(self):
   #     return hash(self.ip_addr)
  
   # def __eq__(self,other):
   #     return isinstance(other, IP_ADDRESS) and self.ip_addr == other.ip_addr
  
   def append_rtt(self,rtt):
       self.rtt.append(round(rtt,3))
       return self
  
   def resolve_ip_to_hostname(self):
       ip_address = self.ip_addr
       try:
           # Get the hostname for the given IP address
           hostname, _, _ = socket.gethostbyaddr(ip_address)
           return hostname
       except socket.herror as e:
           return ip_address


   def create_output_string(self):
       host = self.resolve_ip_to_hostname()
       rs = f" {host} ({self.ip_addr})"
       for i in self.rtt:
           rs += f" {i} ms "
       return rs
      
def calculate_checksum(data):
   checksum = 0
   for i in range(0, len(data), 2):
       checksum += (data[i] << 8) + data[i + 1]
   while checksum >> 16:
       checksum = (checksum & 0xFFFF) + (checksum >> 16)
   checksum = ~checksum & 0xFFFF
   return checksum


def create_scapy_ip_packet(dest_ip, dest_port, ttl):
   # Use Scapy to create an IP packet with TCP layer
   ip_packet = IP(dst=dest_ip, ttl=ttl) / TCP(dport=dest_port, flags="S")
   return bytes(ip_packet)


def send_tcp_syn_packet(dest_ip, dest_port, ttl):
   # Create a raw socket
   raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)       
      
   # Get the Scapy IP packet
   ip_packet = create_scapy_ip_packet(dest_ip, dest_port,ttl)


   # Send the packet
   raw_socket.sendto(ip_packet, (dest_ip, 0))
 
   # print("Send request")
   # Close the raw socket
   raw_socket.close()


def receive_tcp_response():
   # Create a raw socket for receiving
   raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
   raw_socket.settimeout(10)


   try:
       # Wait for the response
       response, _ = raw_socket.recvfrom(4096)
       return response
   except socket.timeout as e:
       # print("Session timeout")
       return None
   except Exception as e:
       print(f"Exception raised: {e}")
       return None
   finally:
       raw_socket.close()
def print_set_of_ips(hop,set_of_ip):
   rs = f"{hop}. "
   length = 0
   for key,ip in set_of_ip.items():
       # print(ip.rtt)
       length += len(ip.rtt)
       rs = rs + ip.create_output_string()
   if length < 3:
       while length < 3:
           rs = rs + " * "
           length += 1
   print(rs)


def resolve_domain_to_ip(domain):
   try:
       ip_address = socket.gethostbyname(domain)
       # print(ip_address)
       return ip_address
   except socket.error as e:
       print(f"Unable to resolve domain to IP: {e}")
       return None
  
def get_args():
   parser = argparse.ArgumentParser(description="TCP Traceroute Tool")
   parser.add_argument("-m", "--max-hops", type=int, default=30, help="Max hops to probe (default = 30)")
   parser.add_argument("-p", "--dest-port", type=int, default=80, help="TCP destination port (default = 80)")
   parser.add_argument("-t", "--target", required=True, help="Target domain or IP")
   args = parser.parse_args()
   return args


def add_default_values(args):
   
   global MAX_HOP
   MAX_HOP = int(args.max_hops)




def tracerouter(args):
   # Example usage
   destination_ip = resolve_domain_to_ip(args.target)
   if destination_ip == None:
       print("Unable to resolve the domain name")
       return
      
   destination_port = args.dest_port
  
   print(f"Traceroute to {args.target}, {MAX_HOP} hops max, TCP SYN to port {destination_port}")
   # Send TCP packet with SYN flag using Scapy for creating the IP packet
   for i in range(1,MAX_HOP+1):
       set_of_ip_addresses = {}
       for j in range(0,3):
           start_time = time.time()
      
           send_tcp_syn_packet(destination_ip, destination_port, i)


           # Receive TCP response
           response = receive_tcp_response()
           # print("Response")
           # print(response == None)
           rtt = (time.time() - start_time) * 1000
  
           if response != None:
              
               response = IP(response)
               # print(response.src)
               ip_addr = IP_ADDRESS(response.src,rtt)
              
               if ip_addr.ip_addr in set_of_ip_addresses:
                   set_of_ip_addresses[ip_addr.ip_addr].append_rtt(rtt)
               else:
                   set_of_ip_addresses[ip_addr.ip_addr] = ip_addr
           else:
               # print("No response received")
               pass
          
              
           time.sleep(0.2)
       # print("________________________")
       print_set_of_ips(i,set_of_ip_addresses)
      
       if destination_ip in set_of_ip_addresses:
           break    
      


if __name__ == "__main__":
   args = get_args()
   add_default_values(args)
   tracerouter(args)


