import pyshark
import socket
import time
import threading
from datetime import datetime
import joblib
from sklearn.ensemble import RandomForestClassifier
import warnings
import subprocess
from kivy.app import App
from kivy.clock import mainthread
from kivy.uix.widget import Widget
from kivy.uix.gridlayout import GridLayout
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
import warnings
warnings.filterwarnings('ignore')

class UILayout(Widget):
    
    def __init__(self, **kwargs):
        super(UILayout, self).__init__(**kwargs)
        
        self.blk = False
        
        self.thread = threading.Thread(target=self.calculate)
    
    def start(self):
        start_btn = self.ids.start
        
        if start_btn.text == 'START':
            start_btn.text = 'STOP'
            self.thread.start()
        else:
            start_btn.text = 'START'
    
    def block(self):
        block = self.ids.block
        
        if block.text == 'BOCK ALL (OFF)':
            block.text = 'BLOCK ALL (ON)'
            self.blk = True
        else:
            block.text = 'BOCK ALL (OFF)'
            self.blk = False
        
    @mainthread    
    def add_record(self, date, tim, ip, port, dat):
        container = self.ids.rows
        row = BoxLayout(size_hint_y=None, height=40, pos_hint={'top': 1})
        
        self.ids.sttl.text = f"Source TTL: {str(dat[5])} ms"
        self.ids.dttl.text = f"Destination TTL: {str(dat[6])} ms"
        self.ids.dbyte.text = f"Destination Byte Rate: {str(dat[8])} B/s"
        self.ids.sbyte.text = f"Source Byte Rate: {str(dat[7])} B/s"
        
        date_ = Label(text = date, color=(1, 0, 0, 1))
        time_ = Label(text = tim, color=(1, 0, 0, 1))
        ip_ = Label(text = ip, color=(1, 0, 0, 1))
        port_ = Label(text = port, color=(1, 0, 0, 1))
        
        row.add_widget(date_)
        row.add_widget(time_)
        row.add_widget(ip_)
        row.add_widget(port_)
        
        container.add_widget(row)
        
    def firewall(self, ip, port):
        cmd = ["iptables", "-A", "INPUT", "-s", ip, "-p", "tcp", "--dport", str(port), "-j", "DROP"]
        subprocess.run(cmd, check=True)

    def calculate(self):
        
        interface = 'wlo1'
        packet_count = 100000
        
        clf = joblib.load('model.joblib')
        # Open a live capture on the specified interface
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        sys_ip = s.getsockname()[0]
        s.close()
        
        capture = pyshark.LiveCapture(interface=interface)

        # Initialize variables to calculate mean and count of TCP window sizes
        total_window_size = 0
        received_packets = 0
        
        s_packet_count = {}
        d_packet_count = {}
        s_bytes_count = {}
        d_bytes_count = {}
        s_time = {}
        d_time = {}
        packet_map = {}
        reset = False

        # Capture the specified number of packets
        for packet in capture.sniff_continuously():
            if 'TCP' in packet:
                # try:
                #     window_size = int(packet['TCP'].window_size)
                #     total_window_size += window_size
                #     received_packets += 1
                #     """ Average tcp window size """
                #     print(f"Current Average Window Size: {total_window_size / received_packets} bytes")
                # except ValueError:
                #     pass
                
                protocol = packet.transport_layer
                src_ip = packet.ip.src
                src_port = packet[protocol].srcport
                
                dst_ip = packet.ip.dst
                dst_port = packet[protocol].dstport
                
                # src_map = str(src_ip) + ',' + str(src_port)
                # dst_map = str(dst_ip) + ',' + str(dst_port)
                
                src_map = (src_ip, src_port)
                dst_map = (dst_ip, dst_port)
                
                (x, y) = (src_map, dst_map)
                
                if ((x, y) or (y, x)) not in packet_map:
                    if not src_ip == sys_ip:
                        packet_map[(src_map, dst_map)] = [113, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
                    if not dst_ip == sys_ip:
                        packet_map[(dst_map, src_map)] = [113, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
                
                # spkts
                if not src_ip == sys_ip:
                    if src_map not in s_packet_count:
                        s_packet_count[src_map] = 1
                    else:
                        s_packet_count[src_map] += 1
                        
                    if reset:
                        s_packet_count[src_map] = 1
                    
                    packet_map[(src_map, dst_map)][1] = s_packet_count[src_map]
                    
                # dpkts
                if not dst_ip == sys_ip:
                    if dst_map not in d_packet_count:
                        d_packet_count[dst_map] = 1
                    else:
                        d_packet_count[dst_map] += 1
                    
                    if reset:
                        d_packet_count[dst_map] = 1
                    
                    packet_map[(dst_map, src_map)][2] = d_packet_count[dst_map]
                
                reset = False 
                # sbytes
                if not src_ip == sys_ip:
                    if src_map not in s_bytes_count:
                        s_bytes_count[src_map] = int(packet.tcp.len)
                    else:
                        s_bytes_count[src_map] += int(packet.tcp.len)
                        s_bytes_count[src_map] = s_bytes_count[src_map] % (2.5 * 1e7)
                        reset = (s_bytes_count[src_map] == 0) 
                    # print(f"sbytes {src_map}: {s_bytes_count[src_map]}")
                    
                    packet_map[(src_map, dst_map)][3] = s_bytes_count[src_map]
                        
                # dbytes
                if not dst_ip == sys_ip:
                    if dst_map not in d_bytes_count:
                        d_bytes_count[dst_map] = int(packet.tcp.len)
                    else:
                        d_bytes_count[dst_map] += int(packet.tcp.len)
                        d_bytes_count[dst_map] = d_bytes_count[dst_map] % (2.5 * 1e7)
                        reset = (d_bytes_count[dst_map] == 0)
                    # print(f"dbytes {dst_map}: {d_bytes_count[dst_map]}")
                    
                    packet_map[(dst_map, src_map)][4] = d_bytes_count[dst_map]
                    
                
                """ IP header length """    
                header_length = int(packet['IP'].hdr_len)
                # print(f"Header length: {header_length} bytes")
                
                """ TCP payload size """
                tcp_payload = int(packet.tcp.len)
                # print(f"TCP payload : {tcp_payload}")
                
                """ ttl """
                if dst_ip == sys_ip:
                    sttl = packet.ip.ttl
                    # print(f"sttl : {sttl}")
                    
                    packet_map[(src_map, dst_map)][5] = int(sttl)
                elif src_ip == sys_ip:
                    dttl = packet.ip.ttl
                    # print(f"dttl : {dttl}")
                    packet_map[(dst_map, src_map)][6] = int(dttl)
                
                # stime
                if not src_ip == sys_ip:
                    if src_map not in s_time:
                        s_time[src_map] = {}
                        s_time[src_map][0] =  time.time()
                        s_time[src_map][1] = 0.0
                        # print(f"sload {src_map} : 0")
                        # print sload = 0
                        
                        packet_map[(src_map, dst_map)][7] = 0.0
                    else:
                        s_time[src_map][1] = time.time() - s_time[src_map][0]
                        # print sload = sbytes * 8 / stime
                        # print(f"sload {src_map} = {(s_bytes_count[src_map] * 8) / s_time[src_map][1]}")
                        packet_map[(src_map, dst_map)][7] = ((s_bytes_count[src_map] * 8) / s_time[src_map][1])
                        
                # dtime
                if not dst_ip == sys_ip:
                    if dst_map not in d_time:
                        d_time[dst_map] = {}
                        d_time[dst_map][0] =  time.time()
                        d_time[dst_map][1] = 0.0
                        # print dload = 0
                        # print(f"dload {dst_map} : 0")
                        
                        packet_map[(dst_map, src_map)][8] = 0.0
                    else:
                        d_time[dst_map][1] = time.time() - d_time[dst_map][0]
                        # print dload = dbytes * 8 / dtime
                        # print(f"sload {dst_map} = {(d_bytes_count[dst_map] * 8) / d_time[dst_map][1]}")
                        packet_map[(dst_map, src_map)][8] = ((d_bytes_count[dst_map] * 8) / d_time[dst_map][1])
                    
                
                if not src_ip == sys_ip:
                    # print(packet_map[(src_map, dst_map)])
                    pred = clf.predict([packet_map[(src_map, dst_map)]])
                    if pred[0] == 1:
                    #     print((src_ip, dst_ip))
                        print(f"{(src_map, dst_map)} = {packet_map[(src_map, dst_map)]}")
                        self.add_record(datetime.now().strftime("%m-%d-%Y"), datetime.now().strftime("%H:%M:%S"), src_map[0], src_map[1], packet_map[(src_map, dst_map)])
                    
                if not dst_ip == sys_ip:
                # if 1 == 1:
                    # print(packet_map[(dst_map, src_map)])
                    pred = clf.predict([packet_map[(dst_map, src_map)]])
                    # print(pred)
                    if pred[0] == 1:
                    #     print((src_ip, dst_ip))
                        # print(f"{(dst_map, src_map)} = {packet_map[(dst_map, src_map)]}")
                        self.add_record(datetime.now().strftime("%m-%d-%Y"), datetime.now().strftime("%H:%M:%S"), dst_map[0], dst_map[1], packet_map[(dst_map, src_map)])            

class WAFApp(App):
    
    def build(self):
        return UILayout()

if __name__ == "__main__":
    app = WAFApp()
    app.run()
    warnings.filterwarnings('ignore')