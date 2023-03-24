import hashlib
import re
from scapy.layers.http import HTTPRequest
from scapy.all import *
import tkinter
import threading
import time

packet_filter = "ip"
idsGui = tkinter.Tk()
idsGui.title("Suspicious Alerts!")

idsList = tkinter.Listbox(idsGui, height=5)
idsList.pack(fill=tkinter.BOTH, expand=True)
behave_idsList = tkinter.Listbox(idsGui, height=5)
behave_idsList.pack(fill=tkinter.BOTH, expand=True)

def print_gui(content):
   idsList.insert(tkinter.END, content)  # Add the alert to the Listbox
   idsGui.update() # Update the GUI
   time.sleep(0.5)

def behave_print_gui(content):
   behave_idsList.insert(tkinter.END, content)  # Add the alert to the Listbox
   idsGui.update() # Update the GUI
   time.sleep(0.5)

# ------------------------------------------------- Start of the Signature-based and Anomaly-based IDS ----------------------------------------------------------
# Whitelist IP addresses
blacklisted_ips = ['175.45.176.1','175.45.176.2','175.45.176.3','175.45.176.4','175.45.176.5','175.45.176.6','175.45.176.7','175.45.176.8',
                   '175.45.176.9','175.45.176.10','175.45.176.11','175.45.176.12','175.45.176.13','175.45.176.14','175.45.176.15','175.45.176.16',
                   '175.45.176.17','175.45.176.18','175.45.176.19','175.45.176.20','175.45.176.21','175.45.176.22','175.45.176.23','175.45.176.24',
                   '175.45.176.25','175.45.176.26','175.45.176.27','175.45.176.28','175.45.176.29','175.45.176.30','175.45.176.31','175.45.176.32',
                   '175.45.176.33','175.45.176.34','175.45.176.35','175.45.176.36','175.45.176.37','175.45.176.38','175.45.176.39','175.45.176.40',
                   '175.45.176.41','175.45.176.42','175.45.176.43','175.45.176.44','175.45.176.45','175.45.176.46','175.45.176.47','175.45.176.48',
                   '175.45.176.49','175.45.176.50','175.45.176.51','175.45.176.52','175.45.176.53','175.45.176.54','175.45.176.55','175.45.176.56',
                   '175.45.176.57','175.45.176.58','175.45.176.59','175.45.176.60','175.45.176.61','175.45.176.62','175.45.176.63','175.45.176.64',
                   '175.45.176.65','175.45.176.66','175.45.176.67','175.45.176.68','175.45.176.69','175.45.176.70','175.45.176.71','175.45.176.72',
                   '175.45.176.73','175.45.176.74','175.45.176.75','175.45.176.76','175.45.176.77','175.45.176.78','175.45.176.79','175.45.176.80',
                   '175.45.176.81','175.45.176.82','175.45.176.83','175.45.176.84','175.45.176.85','175.45.176.86','175.45.176.87','175.45.176.88',
                   '175.45.176.89','175.45.176.90','175.45.176.91','175.45.176.92','175.45.176.93','175.45.176.94','175.45.176.95','175.45.176.96',
                   '175.45.176.97','175.45.176.98','175.45.176.99','175.45.176.100',]


# Define suspicious file hashes. Sha-256 hashes are from MalwareBazaar
suspicious_hashes = ['f0ec980108157002c8ca92507a2caa1f9a2cfa548959c7b1a2533ab7030966ee', 'e8ee3634afde1b13836ca2183216b38956942300ce6f73ac218152cc7baa47f7',
                     '3e29f918baf660aef18adcb2e4962d529fefe3c107ecc011c4b06990b459aa94', 'a56f5f192556bdb3fd7af7a7d03750cbb4473b14ecde429a39a1b80ab6c6ab67',
                     'f5943aa806d8828e433b048522096303f73d796305e366d46318a98ec92e58cb', '0c1d1a60a0fc143c9fc830be48c53d488b414921cf4d97d66466ff2a628d1b4d',
                     '75ccb4fade3b19d0574d859667ef2d5ed6cf2071303a131aa8f8abb0fbb8852f', '9bb31ac6d350fec7927ae213adec3f4363b815c7afce36495286a3c281db5412',
                     '21a330c2b9f07801c498eb4c036dd4ecad7feffea90bbddfa61bc4e1fabca647', '1cae7e40933c543d85b22fd00cf88898a5daa6118c8c50e9875472736a53eb7c',
                     '563b4ec92052a7a150d5f93413498e715ecabdbba2e828e4ba446755b6ac3852', '0a556897a6b882c9859d41ac0bd8f0eb91a7485acbfb2cdf786ea0d11a6ccb17',
                     'b9cceeddd1c1b538557dc237655d9a5cffa9911801856e5d1a8dd9a7dd9031e5', '680a2f01fd134d4ce065aa8bcd5b9dad28fce2e11abbc8d7a637799de8b0240b',
                     'aa24ad12f53cfa81a839a1bab651cf56080c211c010396a9cece73e69a798a78', '5ff8b467d69f22d3119d2834cc1c0bbbb367b515b14ab697ad997e8acbcd5955', 
                     'e8cf6f82a1336b76abb170337985906454f142c5cca33f6aec3591643eaf3268', '155598b67a1707e34f610855d93cd781e1f02e9dd23c54187befb0c51d6528d4',
                     '563b4ec92052a7a150d5f93413498e715ecabdbba2e828e4ba446755b6ac3852', '9d66a5cefbcd4bdc4719a279ce6734c6d7a179533304d9c6838a3e9f3dad6974',
                     'eb9c18761c2133a7de7b3787953ecb4af5a9c57784201ee979db7e825474915f', '4c621cf443f577661f13edfa166a56f18b413eb42f5f8121a0780016557d0545',
                     '0a556897a6b882c9859d41ac0bd8f0eb91a7485acbfb2cdf786ea0d11a6ccb17', 'ab0fb6f529e19da9075e7b3837fd538510e90d64f19bc44e611422a8ed432d6e', 
                     '430b364616ea6534a53a4bdc2e38d74edec19311de5d21ae951c2683d5ecc969', 'c7d883cb4ffb1f9a9c19c30e46b5b0180a253d7e02350a5252bfaff1e69bc125',
                     'd65ff348b355affe66cf32d1e054d9b8ebf22757642a678c6a55e821c647191a', 'a7d1ef142714d3f73c7ae9e9964a13d721b19cb8e7d6fe28527eb741dd4b4c5e',
                     '63b9f8c530df2ba68fb98764471ad063e2fa74a25334c0179dccc83a549dee3f', '997c73cd1e75587de8ddbdbabc4527454f80eb06515efe6f5d8d0bae39e0dfa0',
                     '901d0d19ba4a552a8fd41451dd2143a6338376b15b37ed0adc167da496d547b0', '281df1c5c4f47ae357ef5f8617166bb8044fdb0e0f6b334fb8135833451340bd',
                     'f2f80e624a3bcaec31ecb73a8d75715189b7baa73176fa773a986ff80c19976d', 'fd14ec3cdfb9034a19e48717b697a4d1b169c02d24be9ac06b7c876388e1d9ae',
                     '61f0e80b2a74bf26d2089e09e779b0514b4d7e324de6f968bb224cbe6f2fab91', '00c4b01417f71763724949ffb123875e62fb8e79ce17ae1ab224acb9261221c7',
                     '99613561041525ed0afc6831e5bbe4643ab5cbce4ec6633d13672d4536edfd7c', 'feedf0ce6bd3277beb6c61ce041e1f7da8728399d3096ad8b635fcf1705c3531',
                     'b0616290928a4dc2b15cd8a0e1ab6be754cfc6c4d46bc50f4dfbc3234a364966', '5bdf181c629182a48ce6810cd0987fb0c1242ded4c9e73501df59481dbe6ec3a',
                     '2e9b8db393b9d57061144c9ca41a2780403b2083628cc630a0c627207d9d43be', '7fa53adc326d8a45b36a04c69a7fbc8f5f1651d1cac4fcc9a03fd34ef4aca914',
                     '1e13c8a7c2b89db3cf0f5d84ae88f5a6a12ca10c4673ad0297dfde1445626d0d', '710709a200a5cda2a4293e9de521ab65d23170ab8bca04c8c7af22f86091d5d7',
                     '053877cae27e1b2cb0aac24b5a562736be62d2756dc9897eca8e72e39ff385f9', '3b07ad25ee1df777dc55b81828866fd88ac45020d0de4747b75b105f1f953e4e']

# Define suspicious URL patterns
suspicious_url_pattern = [
   r".*\/(\.\.\/)+",  # Directory traversal attempt
   r".*\/(passwd|shadow|group)$",  # Password file access attempt
   r".*\/(etc|proc|var\/log)\/.*",  # System file access attempt
   r".*\/(bin|usr\/bin|usr\/local\/bin)\/.*",  # Binary file access attempt
   r".*\.(msi|exe|dll|cmd|bat|ps1|vbs|hta)$", # Windows executable file access or download attempt
   r".*\/(powershell|cmd|command|wmic)\/.*" # Command injection or PowerShell access attempt
   r".*\/(cmd|exec|eval|system|passthru|shell_exec|popen)\/.*",  # Command execution attempt
   r".*\/(cmd\.exe|cmd\.php|cmd\.jsp|cmd\.asp)\/.*",  # Command injection attempt
   r".*\.(zip|tar|gz)$" # Suspicious archive file download
   r".*\/(bin|cgi|fcgi|php|pl|py|rb|sh)\/.*" # Script file access attempt
   r".*\/(config|conf|cfg|settings|ini)\/.*" # Configuration file access attempt
   r".*\/(debug|test|demo|example)\/.*" # Development or testing URL
   r".*\/(backup|old|archive)\/.*" # Backup or archive file access attempt
   r".*\/(update|upgrade|patch|install)\/.*" # Software update or installation attempt
   r".*\/(download|get|fetch)\/.*" # Suspicious file download attempt
   r".*\/(cron|scheduled)\/.*" # Cron job or scheduled task URL
]

# Define suspicious packet payload patterns
suspicious_payload_pattern = [
   "RIFF....WAVEfmt",  # Indicates a WAV audio file
   "Rar!",  # Indicates a RAR archive file
   "7z¼¯'¸",  # Indicates a 7-Zip archive file
   "\x50\x4B\x03\x04",  # Indicates a ZIP archive file
   "ustar",  # Indicates a Unix TAR archive file
   "PK\x03\x04",  # Indicates a 7-Zip, PKZIP, or WinZip archive file
   "SQLite format 3",  # Indicates a SQLite database file
   "#!/bin/bash",  # Indicates a shell script file
   "\x1F\x8B\x08",  # Indicates a GZIP compressed file
   "\x42\x5A\x68",  # Indicates a BZIP2 compressed file
   "\x50\x4B\x03\x04",  # Indicates a ZIP archive file
   "ssh-",  # Indicates an SSH key file
   "\x1F\x9D",  # Indicates a compress compressed file
   "\x1F\xA0",  # Indicates a lzop compressed file
   "\xFD\x37\x7A\x58\x5A\x00",  # Indicates an xz compressed file
   "\x42\x5A\x68\x39\x31\x41\x59\x26\x53\x59",  # Indicates a BZIP2 compressed file
   "\x1F\x8B\x08\x00\x00\x00\x00\x00",  # Indicates a GZIP compressed file
   "\x75\x73\x74\x61\x72",  # Indicates a tar archive file
   "BEGIN RSA PRIVATE KEY",  # Indicates an RSA private key file
   "BEGIN DSA PRIVATE KEY",  # Indicates a DSA private key file
   "BEGIN EC PRIVATE KEY"  # Indicates an EC private key file
]


# Define suspicious packet header values
suspicious_headers = {
    "User-Agent": ["hack", "exploit", "malware"],
    "Referer": ["evil.com", "hacker.com", "malware.com"],
    "Accept-Language": ["ru", "cn"],
    "Cookie": ["admin", "root"],
    "Authorization": ["Basic", "Digest"],
}

# Define the IP address of the network to monitor
network_ip = "10.0.2"

# Define the start and end times of the workday
start_time = "06:00:00"
end_time = "19:00:00"

# Define the maximum amount of data that can be transferred during the workday
max_data_transfer = 1000

# Define a dictionary to store the data transfer for each IP address
data_transfer = {}


# Define a function to detect suspicious packets
def detect_packet(packet):
   #Check for suspicious IP addresses
   if IP in packet:
      ip_src = packet[IP].src
      ip_dst = packet[IP].dst
      if ip_src in blacklisted_ips or ip_dst in blacklisted_ips:
         sus_alert = f'Suspicious IP address detected: Source - {packet[IP].src} | Destination - {packet[IP].dst}'
         print_gui(sus_alert)

   # Check for suspicious file hashes
   if Raw in packet:
      payload = packet[Raw].load
      file_hash = hashlib.sha256(payload).hexdigest()
      if file_hash in suspicious_hashes:
         sus_alert = f'Suspicious file hash detected: Source - {packet[IP].src} | File Hash - {file_hash}'
         print_gui(sus_alert)

   #  Check for suspicious URL patterns      
   if packet.haslayer(HTTPRequest):
      url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
      # Check if the URL matches any of the suspicious URL patterns
      for pattern in suspicious_url_pattern:
         if re.match(pattern, url):
            sus_alert = f'Suspicious URL pattern detected: Source - {packet[IP].src} | Payload - {payload}'
            print_gui(sus_alert)


   # Check for suspicious packet payload patterns
   if TCP in packet and packet[TCP].payload:
      payload = str(packet[TCP].payload)
      for pattern in suspicious_payload_pattern:
         if re.search(pattern, payload):
            sus_alert = f'Suspicious packet payload detected: Source - {packet[IP].src} | Payload - {payload}'
            print_gui(sus_alert)

   # Check for suspicious headers
   for header in suspicious_headers:
      if header in packet:
         for value in suspicious_headers[header]:
            if value in packet[header]:
               sus_alert = f"Suspicious packet header detected: Source - {packet[IP].src} | Payload - {packet.summary()}"
               print_gui(sus_alert)

   # Check for suspicious packet sizes (Data exfiltration)
   if TCP in packet and packet[TCP].payload:
      payload_length = len(packet[TCP].payload)
      tcp_header_length = len(packet[TCP])
      expected_length = tcp_header_length + payload_length
      actual_length = len(packet)
      if actual_length > expected_length * 3 or actual_length < expected_length * 0.03:
         behave_sus_alert = f"Packet size is suspicious! Expected {expected_length}, got {actual_length} | Source - {packet[IP].src}"
         behave_print_gui(sus_alert)
   
   # Check if the packet is an IP packet
   if IP in packet:
      # Get the source IP addresses
      src_ip = packet[IP].src
      # Check if the source IP address is part of the network to monitor
      if src_ip.startswith(network_ip):
         # Check if the current time is during the workday
         current_time = time.strftime("%H:%M:%S", time.localtime())
         
         if start_time <= current_time <= end_time:
            # Update the amount of data transferred for the source IP address
            if src_ip in data_transfer:
               data_transfer[src_ip] += len(packet)
            else:
               data_transfer[src_ip] = len(packet)
            # Check if the amount of data transferred exceeds the maximum
            if data_transfer[src_ip] > max_data_transfer:
               behave_sus_alert = f"Anomalous traffic detected! Expected size: {max_data_transfer}, got {data_transfer[src_ip]} | Source - {packet[IP].src}"
               behave_print_gui(behave_sus_alert)
               data_transfer[src_ip] = 0
         
         else:
            behave_sus_alert = f"Anomalous traffic detected! Expected time: {start_time} - {end_time}, got {current_time} | Source - {packet[IP].src}"
            behave_print_gui(behave_sus_alert)
         

# Set the monitoring time and packet count threshold
monitoring_time = 10 # in seconds
threshold = 100 # number of packets
pkt_count = 0 # packet count

def monitor_traffic(pkt):
    # Count the number of packets seen so far
    global pkt_count
    pkt_count += 1
    
    # If the number of packets exceeds a threshold, generate an alert
    if pkt_count > threshold:  
      behave_sus_alert = f"Anomalous traffic volume detected: {pkt_count} packets in {monitoring_time} seconds"
      behave_print_gui(behave_sus_alert)




# --------------------------------- Start of the Main functions of the IDS -------------------------------------------------

def d_packet():
   try:
      sniff(filter=packet_filter, prn=detect_packet)
   except:
      pass

def m_packet():
   try:
      sniff(timeout=monitoring_time, prn=monitor_traffic)
   except:
      pass

thread_detect = threading.Thread(target=d_packet)
thread_monitor = threading.Thread(target=m_packet)

thread_detect.start()
thread_monitor.start()
idsGui.mainloop()
thread_detect.join()
thread_monitor.join()
