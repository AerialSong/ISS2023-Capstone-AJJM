<h1>Readme for SCORIA v.1.0 All-in-One IDS Suite for Home/Small-Business Infrastructures</h1>
<h2>Designed by:</h2>
    <p>Joseph Benedith<br>
    Mackenzie Cleland<br>
    Arthur Kutepov<br>
    Jomel Jay Segundo</p>

<h2>1. Running Scoria</h2>

To run Scoria, simply run:
    <code>$ sudo python3 launcher.py</code>

**IMPORTANT:** All scripts (along with config.txt, once present) <em>must be in the same folder</em> in order for Scoria to run correctly!!!

<h2>2. Functionality</h2>

The Scoria All-in-One IDS Suite contains the following functionality:
Signature-based IDS software
Live-input packet sniffer
Port scanning software
Cloud-based log exportation software

This is detailed below:

<h3>a. Signature-Based IDS Software (sigids.py, netmon.py)</h3>


<h3>b. Live-Input Packet Sniffer (sniffer.py, linput.py)</h3>


<h3>c. Port-Scanning Software (ports.py)</h3>


<h3>d. Cloud-Based Log Exportation Software (netlog.py, s3nder.py)</h3>



<h2>3. Important Information Regarding Live-Input</h2>

In order to perform live-input packet-sniffing, initiate the necessary script by running:
<code>  >>> linput.py</code>
In the python3 terminal which Scoria starts up, with any necessary arguments in the usual syntax.
