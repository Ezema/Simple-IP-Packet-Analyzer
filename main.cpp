#include <iostream>  // for input/output operations
#include <pcap.h>    // for packet capture functionality
#include <netinet/ip.h>      // for internet address family constants and types
#include <netinet/if_ether.h>    // for ethernet header structure


/**
 * This function is called every time a packet is captured.
 * It extracts the source and destination IP addresses from the packet
 * and prints them to the console.
 */
void processPacket(u_char* arg, const pcap_pkthdr* packetHeader, const u_char* packetData) {
    // Extract the Ethernet header from the packet data
    ether_header* ethernetHeader = (ether_header*) packetData;

    // Check if the Ethernet header contains an IP packet
    if (ntohs(ethernetHeader->ether_type) != ETHERTYPE_IP) {
        // Not an IP packet, ignore it
        return;
    }

    // Extract the IP header from the packet data
    ip* ipHeader = (ip*)(packetData + sizeof(ether_header));

    // Extract the source and destination IP addresses from the IP header
    in_addr_t sourceIp = ipHeader->ip_src.s_addr;
    in_addr_t destIp = ipHeader->ip_dst.s_addr;

    // Convert the source and destination IP addresses to strings
    char sourceIpString[INET_ADDRSTRLEN];
    char destIpString[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &sourceIp, sourceIpString, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &destIp, destIpString, INET_ADDRSTRLEN);

    // Print the source and destination IP addresses to the console
    std::cout << "Source IP: " << sourceIpString << std::endl;
    std::cout << "Dest IP: " << destIpString << std::endl;
    std::cout << "============================"<< std::endl;
}

int main() {
    // Find the first available network device
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding device: " << errbuf << std::endl;
        return 1;
    }
    char* device = alldevs->name;

    // Open the network device for live capture
    pcap_t* pcapHandle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (pcapHandle == nullptr) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        return 1;
    }

    // Start capturing packets and process them using the processPacket function
    pcap_loop(pcapHandle, -1, processPacket, nullptr);

    // Free the device list and close the network device handle
    pcap_freealldevs(alldevs);
    pcap_close(pcapHandle);

    return 0;
}
