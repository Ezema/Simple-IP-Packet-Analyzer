# Packet Analyzer

A simple packet analyzer that captures and displays IP packets.

## Prerequisites

To compile and run this program, you will need to have the following software installed on your system:

- C++ compiler
- PCAP library

## Installation

1. Clone the repository:
git clone https://github.com/ezema/simple-IP-packet-analyzer.git
2. Change directory to the cloned repository:
cd packet-analyzer
3. Compile the program using your C++ compiler:
g++ -o packet-analyzer packet-analyzer.cpp -lpcap

## Usage

1. Run the program:
sudo ./packet-analyzer
2. The program will start capturing packets on the default capture device and displaying packet information on the console.



