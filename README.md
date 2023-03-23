<h1>Readme for SCORIA v.1.0 All-in-One IDS Suite for Home/Small-Business Infrastructures</h1>
<h2>Designed by:</h2>
    <p>Joseph Benedith<br>
    Mackenzie Cleland<br>
    Arthur Kutepov<br>
    Jomel Jay Segundo</p>

<h2>1. Running Scoria</h2>

To run Scoria, simply run:<br>
    <code>$ sudo python3 launcher.py</code>

**IMPORTANT:** All scripts (along with config.txt, once present) <em>must be in the same folder</em> in order for Scoria to run correctly!!!

<h2>2. Functionality</h2>

The Scoria All-in-One IDS Suite contains the following functionality:<br>
Signature-based IDS software<br>
Live-input packet sniffer<br>
Port scanning software<br>
Cloud-based log exportation software<br>

This is detailed below:

<h3>a. Signature-Based IDS Software (sigids.py, netmon.py)</h3>


<h3>b. Live-Input Packet Sniffer (sniffer.py, linput.py)</h3>
This application allows a user to sniff for network packets and filter for custom characteristics. For instance, if a user wanted to only output TCP packets with the destination IP 10.20.30.4, the syntax would be: 
sudo ./sniffer.py -dest 10.20.30.4 -pr TCP
This allows for a constant and uninterrupted workflow, and with the --sleep option, a user can pause output after each packet for an easier to follow output.
The Live input functionality is performed via linput.py. As sniffer.py is running, a user may send brand new arguments for filtering to the output. If sniffer is output packets that filter for source IP 30.40.50.6, and during this output a user decides to filter for source IP 20.40.60.8 instead, the run this command in the newly opened terminal:
./linput.py -s 20.40.60.8
sniffer.py would read this new filter instruction and print accordingly


<h3>c. Port-Scanning Software (ports.py)</h3>


<h3>d. Cloud-Based Log Exportation Software (netlog.py, s3nder.py)</h3>



<h2>3. Important Information Regarding Live-Input</h2>

In order to perform live-input packet-sniffing, initiate the necessary script by running:<br>
<code>>>> linput.py</code><br>
In the new user terminal window which Scoria starts up, with any necessary arguments in the usual syntax.
