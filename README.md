Readme for SCORIA v.1.0 All-in-One IDS Suite for Home/Small-Business Infrastructures
Designed by:
    Joseph Benedith
    Mackenzie Cleland
    Arthur Kutepov
    Jomel Jay Segundo

1. Running Scoria

To run Scoria, simply run:
    $ sudo python3 launcher.py

IMPORTANT: All scripts (along with config.txt, once present) must be in the same folder in order for Scoria to run correctly!!!

2. Functionality

The Scoria All-in-One IDS Suite contains the following functionality:
Signature-based IDS software
Live-input packet sniffer
Port scanning software
Cloud-based log exportation software

This is detailed below:

a. Signature-Based IDS Software (sigids.py, netmon.py)


b. Live-Input Packet Sniffer (sniffer.py, linput.py)


c. Port-Scanning Software (ports.py)


d. Cloud-Based Log Exportation Software (netlog.py, send3r.py)



3. Important Information Regarding Live-Input

In order to perform live-input packet-sniffing, initiate the necessary script by running:
    >>> linput.py
In the python3 terminal which Scoria starts up, with any necessary arguments in the usual syntax.
