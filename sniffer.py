from scapy.all import sniff, IP, TCP, UDP, DNS

def analyze_packet(packet):

    if IP in packet:
        ip = packet[IP]

        print("\n---------------------------")
        print("Source IP:", ip.src)
        print("Destination IP:", ip.dst)

        if TCP in packet:
            print("Protocol: TCP")
            print("Source Port:", packet[TCP].sport)
            print("Destination Port:", packet[TCP].dport)

        elif UDP in packet:
            print("Protocol: UDP")
            print("Source Port:", packet[UDP].sport)
            print("Destination Port:", packet[UDP].dport)

        if DNS in packet:
            dns = packet[DNS]
            if dns.qr == 0:
                print("DNS Query:", dns.qd.qname.decode())
            else:
                print("DNS Response")

sniff(prn=analyze_packet)
