from __future__ import print_function
from scapy.all import *
import requests
import json

__version__ = "0.0.3"
info = ''


# Hàm sửa lỗi để trích xuất các tùy chọn DHCP theo khóa
def get_option(dhcp_options, key):
    # Định nghĩa danh sách các tùy chọn cần giải mã
    must_decode = ['hostname', 'domain', 'vendor_class_id']
    try:
        # Duyệt qua các tùy chọn DHCP
        for i in dhcp_options:
            # Kiểm tra xem tùy chọn hiện tại có khớp với khóa không
            if i[0] == key:
                # Nếu DHCP Server trả về nhiều máy chủ tên
                # trả về tất cả dưới dạng chuỗi được ngăn cách bằng dấu phẩy.
                if key == 'name_server' and len(i) > 2:
                    return ",".join(i[1:])
                # domain và hostname là chuỗi nhị phân,
                # giải mã thành chuỗi Unicode trước khi trả về
                elif key in must_decode:
                    return i[1].decode()
                else:
                    return i[1]
    except:
        pass


# Hàm xử lý gói tin DHCP
def handle_dhcp_packet(packet):

    global info  # Sử dụng biến toàn cục

    # Match DHCP discover
    if DHCP in packet and packet[DHCP].options[0][1] == 1:
        print('---')
        print('New DHCP Discover')
        info += 'New DHCP Discover\n'
        hostname = get_option(packet[DHCP].options, 'hostname')
        print(f"Host {hostname} ({packet[Ether].src}) asked for an IP")
        info += f"Host {hostname} ({packet[Ether].src}) asked for an IP\n"


    # Match DHCP offer_đề nghị
    elif DHCP in packet and packet[DHCP].options[0][1] == 2:
        print('---')
        print('New DHCP Offer')
        info += 'New DHCP Offer\n'

        subnet_mask = get_option(packet[DHCP].options, 'subnet_mask')
        lease_time = get_option(packet[DHCP].options, 'lease_time')
        router = get_option(packet[DHCP].options, 'router')
        name_server = get_option(packet[DHCP].options, 'name_server')
        domain = get_option(packet[DHCP].options, 'domain')

        print(f"DHCP Server {packet[IP].src} ({packet[Ether].src}) "
              f"offered {packet[BOOTP].yiaddr}")
        
        info += f"DHCP Server {packet[IP].src} ({packet[Ether].src}) offered {packet[BOOTP].yiaddr}\n"


        print(f"DHCP Options: subnet_mask: {subnet_mask}, lease_time: "
              f"{lease_time}, router: {router}, name_server: {name_server}, "
              f"domain: {domain}")
        
        info += f"DHCP Options: subnet_mask: {subnet_mask}, lease_time: {lease_time}, router: {router}, name_server: {name_server}, domain: {domain}\n"


    # Match DHCP request_yêu cầu
    elif DHCP in packet and packet[DHCP].options[0][1] == 3:
        print('---')
        print('New DHCP Request')
        info += 'New DHCP Request\n'

        requested_addr = get_option(packet[DHCP].options, 'requested_addr')
        hostname = get_option(packet[DHCP].options, 'hostname')
        print(f"Host {hostname} ({packet[Ether].src}) requested {requested_addr}")
        info += f"Host {hostname} ({packet[Ether].src}) requested {requested_addr}\n"


    # Match DHCP ack_phê duyệt
    elif DHCP in packet and packet[DHCP].options[0][1] == 5:
        print('---')
        print('New DHCP Ack')
        info += 'New DHCP Ack\n'

        subnet_mask = get_option(packet[DHCP].options, 'subnet_mask')
        lease_time = get_option(packet[DHCP].options, 'lease_time')
        router = get_option(packet[DHCP].options, 'router')
        name_server = get_option(packet[DHCP].options, 'name_server')

        print(f"DHCP Server {packet[IP].src} ({packet[Ether].src}) "
              f"acked {packet[BOOTP].yiaddr}")
        info += f"DHCP Server {packet[IP].src} ({packet[Ether].src}) acked {packet[BOOTP].yiaddr}\n"


        print(f"DHCP Options: subnet_mask: {subnet_mask}, lease_time: "
              f"{lease_time}, router: {router}, name_server: {name_server}")
        info += f"DHCP Options: subnet_mask: {subnet_mask}, lease_time: {lease_time}, router: {router}, name_server: {name_server}\n"


    # Match DHCP inform_thông báo
    elif DHCP in packet and packet[DHCP].options[0][1] == 8:
        print('---')
        print('New DHCP Inform')
        info += 'New DHCP Inform\n'

        hostname = get_option(packet[DHCP].options, 'hostname')
        vendor_class_id = get_option(packet[DHCP].options, 'vendor_class_id')

        print(f"DHCP Inform from {packet[IP].src} ({packet[Ether].src}) "
              f"hostname: {hostname}, vendor_class_id: {vendor_class_id}")
        info += f"DHCP Inform from {packet[IP].src} ({packet[Ether].src}) hostname: {hostname}, vendor_class_id: {vendor_class_id}\n"

    else:
        print('---')
        print('Some Other DHCP Packet')
        info += 'Some Other DHCP Packet\n'
        print(packet.summary())
        print(ls(packet))

    # Đoạn code sau sniffing
    url = 'http://192.168.43.107:5000/api/save_text'
    data = {'text': info}
    
    # Chuyển đổi dữ liệu thành định dạng JSON
    json_data = json.dumps(data)
    
    # Đặt tiêu đề Content-Type là application/json
    headers = {'Content-Type': 'application/json'}

    # Gửi yêu cầu POST với dữ liệu vào API
    response = requests.post(url, data=json_data, headers=headers)

    # In kết quả từ server
    print(response.json())

    return


if __name__ == "__main__":
    sniff(filter="udp and (port 67 or 68)", prn=handle_dhcp_packet)
