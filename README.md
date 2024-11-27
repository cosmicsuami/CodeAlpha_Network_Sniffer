# CodeAlpha_Network_Sniffer

## Overview
Python-based network sniffer developed during the Code Alpha internship program. Monitors and analyzes network traffic in real time, providing insights into data flow and packet details.

## Features
- Packet Capturing and Analysis
- Interception of HTTP requests
- Interception of HTTPS requests using SSL Strip
- Capturing of POST requests sent over HTTP websites

## Installation
No installation is required

### Requirements
- Python 3.8 or higher
- Git
- Scapy
- Colorama
- SSL Strip
- Kali Linux or Other Linux Distribution

## Setup
### Install Dependencies:
  Python (If python is below 3.8): sudo apt install python3 python3-pip -y
  Git: sudo apt install git -y
  Scapy: pip3 install scapy
  Colorama: pip3 install colorama
  SSL Strip: sudo apt install sslstrip -y

##Run Script using the format: sudo python3 ./sniff.py -i <network interface>
