import os
import scapy
import tempfile
from scapy.all import *
from scapy.all import wrpcap
from scapy.layers.inet import Ether
from scapy.layers.inet import UDP
from scapy.layers.inet6 import IPv6, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr
from scapy import sendrecv
from scapy.sendrecv import sendp


def create_pcap_file(packets):
    """ Method to create pcap file """
    fd, path = tempfile.mkstemp(suffix='.pcap')
    os.close(fd)  # close file descriptors to not run out of counts
    wrpcap(path, packets, append=True)
    return path


if __name__ == '__main__':
    import shutil

    dst_ip = 'abcd::2'
    dst_mac = '96:52:e4:45:77:e2'
    src_ip = '2001::43'
    src_mac = '86:61:d9:ee:7c:09'
    pkt_size = 100
    port = 1234
    packet = (Ether(src=src_mac, dst="33:33:ff:00:00:02") /
            IPv6(src=src_ip, dst="ff02::1:ff00:02") /
              ICMPv6ND_NS(tgt=dst_ip) /
              ICMPv6NDOptSrcLLAddr(lladdr=src_mac))
#    if IP in packet:
#        print("ipv4: ",packet[IP])
#    if IPv6 in packet:
#        print("ipv6: ", packet[IPv6])
 
    #print(dir(packet.Ether))
    print(packet[IPv6])
    #del packet[IPv6].chksum 

    packet.show2()
    print("packet is", linehexdump(packet, onlyhex=True, dump=True))
    print("sending packet....")
    sendp(packet, iface='net1')
    print("sent!!!!!!!!!!!!!")
    # payload_size = (pkt_size - 8 - 20 - 18)
    # payload = 'Z' * payload_size
    # packet = packet / payload
    # packet_list = [packet]
    # print(f'pcap for pkt:{pkt_size} and flows: 1')
    # # file1 = create_pcap_file(packet_list)
    # file2 = f'/Users/tanmay/touchstone/touchstone-engine/ve_engines/plugins/voereir_perf_config/prox/intel-pcap-ipv6-1-{pkt_size}-NS'
    # shutil.move(file1, file2)
    # print(f"pcap created in {file2}")

