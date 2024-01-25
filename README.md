# TCP Tracerouter

TCP Tracerouter is a command-line tool replicating the functionality of the `traceroute` command using raw sockets. It sends TCP SYN packets to the destination and ICMP packets for each hop until reaching the target. The tool provides comprehensive details for each hop, including router IP, name, timestamps, maximum hop, and the target.

## Table of Contents

- [Features](#features)
- [Usage](#usage)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Examples](#examples)


## Features

- Trace the path of packets sent over the internet.
- Display router details, including IP and hostname.
- Measure the time taken to reach each router.
- Customize parameters such as max hops, run delay, target, output to file.
- Generate a PDF report of the traceroute.

## Usage

### Prerequisites

Make sure you have the following installed:

- Python 3
- [Scapy](https://scapy.readthedocs.io/)

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/your-username/tcp-tracerouter.git

Certainly! Here's the updated README with navigation, usage, installation, and examples:

markdown
Copy code
# TCP Tracerouter

TCP Tracerouter is a command-line tool replicating the functionality of the `traceroute` command using raw sockets. It sends TCP SYN packets to the destination and ICMP packets for each hop until reaching the target. The tool provides comprehensive details for each hop, including router IP, name, timestamps, maximum hop, and the target.

## Table of Contents

- [Features](#features)
- [Usage](#usage)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Examples](#examples)
- [License](#license)
- [Acknowledgments](#acknowledgments)

## Features

- Trace the path of packets sent over the internet.
- Display router details, including IP and hostname.
- Measure the time taken to reach each router.
- Customize parameters such as max hops, run delay, target, output to file.
- Generate a PDF report of the traceroute.

## Usage

### Prerequisites

Make sure you have the following installed:

- Python 3
- [Scapy](https://scapy.readthedocs.io/)

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/your-username/tcp-tracerouter.git

### Examples

To perform a traceroute, run the following command in your terminal:

```bash
python tcp_tracerouter.py -t <target_domain_or_ip> -m <max_hops> -p <destination_port>

-t: Specify the target domain or IP address.
-m: Set the maximum number of hops (default is 30).
-p: Specify the TCP destination port (default is 80).


