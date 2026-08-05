from scapy.all import rdpcap

print(f"Reading the pcap file...")

packets = rdpcap("test.pcapng")


for packet in packets:
    packet.show()
    input()



def stat():
    #How many packets
    #How many TCP packets
    #How many UDP packets
    #and etc




def threat_checking ():
    #Checking pcap file on man in the middle attacks and etc





def report_generator():
    #coming soon



def main():
    pcap_file = "test.pcapng"

    packets = rdpcap(pcap_file)

    get_statistics(packets)

    threat_checking(packets)

    report_generator([])




if __name__ == "__main__":
    main()






