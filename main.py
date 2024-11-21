from scapy.all import IP, ICMP, UDP, TCP, send
import random

def generate_payload(size):
    """Generate a random payload of specified size."""
    return b"X" * size  # Create binary payload

def send_packet(target_ip, protocol="ICMP"):
    """Send a single spoofed packet to the target."""
    src_ip = "192.168.1.1"  # Use a fixed, valid IP for testing
    
    payload = generate_payload(random.randint(512, 2048))

    try:
        if protocol == "ICMP":
            packet = IP(src=src_ip, dst=target_ip)/ICMP()/payload
        elif protocol == "UDP":
            packet = IP(src=src_ip, dst=target_ip)/UDP(dport=random.randint(1, 65535))/payload
        elif protocol == "TCP":
            packet = IP(src=src_ip, dst=target_ip)/TCP(dport=random.randint(1, 65535), flags="S")/payload
        else:
            print("Unknown protocol")
            return

        send(packet, verbose=0)
        print(f"Packet sent to {target_ip} via {protocol}")
    except Exception as e:
        print(f"Error sending packet: {e}")

if __name__ == "__main__":
    target_ip = input("Enter the target IP address: ")
    protocol = input("Enter the protocol (ICMP/UDP/TCP): ")
    send_packet(target_ip, protocol)
