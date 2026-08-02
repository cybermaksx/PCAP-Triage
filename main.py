from scapy.all import rdpcap

print("Starting analysis...")


packets = rdpcap("test.pcapng")


print(f"✅ Succesfully read : {len(packets)}")


print("\nFirst 3 packets:")
for i in range(3):
    print(f"  {i+1}. {packets[i].summary()}")
