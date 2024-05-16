from scapy.all import *
import time


def listen_dhcp():
    # Make sure it is DHCP with the filter options
    sniff(prn=print_packet, filter='udp and (port 67 or port 68)')
    
def print_packet(packet):
    # khởi tạo các biến ban đầu
    target_mac, requested_ip, hostname, vendor_id = [None] * 4
    
    # lấy các địa chỉ MAC yêu cầu
    if packet.haslayer(Ether):
        target_mac = packet.getlayer(Ether).src
        
    # lấy các tùy chọn DHCP
    dhcp_options = packet[DHCP].options
    for item in dhcp_options:
        try:
            label, value = item
        except ValueError:
            continue
        if label == 'requested_addr':
            # lấy địa chỉ IP được yêu cầu
            requested_ip = value
        elif label == 'hostname':
            # lấy tên của thiết bị
            hostname = value.decode()
        elif label == 'vendor_class_id':
            # lấy mã sản xuất
            vendor_id = value.decode()
    if target_mac and vendor_id and hostname and requested_ip:
        # nếu tất cả các biến là none, in ra thiết bị
        time_now = time.strftime("[%Y-%m-%d - %H:%M:%S]")
        print(f"{time_now} : {target_mac}  -  {hostname} / {vendor_id} requested {requested_ip}")

if __name__ == "__main__":
    listen_dhcp() 
    