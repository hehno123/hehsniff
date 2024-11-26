import time
import sys
import logging
import signal 
import dns.resolver 

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
import argparse

host_being_ping = ''
packet_counter = 0
packet_lost = 0

time_min = 0
time_max = 0
time_sumos = 0
time_start = 0

def is_correct_ip(text):
    if len(text) == 0:
        return False
    splited = text.split(".")
    
    if len(splited) != 4:
        return False

    for i in splited:
        if int(i) < 0 or int(i) > 255:
            return False

    return True

def dns_request(domain):
    try:
        result = dns.resolver.resolve(domain, 'A')
    
        for val in result:
            return val.to_text()

    except:
        try:
            result = dns.resolver.resolve(domain, 'AAAA')
            for val in result:
                return val.to_text()

        except:
            print('Cannot find ip address')
            sys.exit(0)

def send_icmp(ip_address, count):
        iterator = 0
        
        global packet_counter
        global packet_lost
        global time_min
        global time_max
        global time_sumos

        while (count == 0) or (iterator < count):
            packet = IP(dst=ip_address) / ICMP()
            ans = sr1(packet, timeout=5, verbose = False)
            timeout = round((ans.time - packet.sent_time) * 1000, 1) if ans != None else None
            packet_counter = packet_counter + 1

            if ans == None:
                print(f'From {packet.src} icmp_seq={packet.seq} Destination Host Unreachable')
                packet_lost = packet_lost + 1
            
            else:
                print(f'From ({ip_address}): icmp_seq={ans.seq} ttl={ans[IP].ttl} time={timeout} ms')
                time_min = timeout if iterator == 0 else (timeout if timeout < time_min else time_min)
                time_max = timeout if iterator == 0 else (timeout if timeout > time_max else time_max)
                time_sumos = time_sumos + timeout
            
            time.sleep(1)
            iterator = iterator + 1

def parse_arguments():
    global host_being_ping

    parser = argparse.ArgumentParser()
    parser.add_argument("destination")
    parser.add_argument("-c", "--count", action="store")

    args = parser.parse_args()
    is_ip_addr = is_correct_ip(args.destination)

    ip_address = args.destination
    payload = 8
    
    host_being_ping = args.destination

    if (is_ip_addr == False):
        ip_address = dns_request(args.destination)

    if(args.count == None):
        args.count = 0
    
    print(f'PING {args.destination} ({ip_address}) {payload} bytes of data')

    send_icmp(ip_address, int(args.count))


def shutdown(sig, frame):
    if packet_counter != 0 and packet_counter - packet_lost != 0:
            print(f'\n--- {host_being_ping} ping statistics ---')
            print(f'{packet_counter} transmitted, {packet_counter - packet_lost} received, {round(((packet_lost / packet_counter) * 100), 1)}% loss, time ' + str(round(((time.time() - start) * 1000), 0)) + 'ms')
            print(f'rtt min/max/avg = {round(time_min, 3)}/{round(time_max, 3)}/' + str(round((time_sumos / (packet_counter - packet_lost)), 3)) + ' ms')
        
    else:
        print(f'\n0 packets received')

    sys.exit()

def main():
    global start
    start = time.time()
    signal.signal(signal.SIGINT, shutdown)
    parse_arguments()

if __name__ == "__main__":
    main()    
