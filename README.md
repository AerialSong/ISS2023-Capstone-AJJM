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
Port scanning software<br>
Live-input packet sniffer<br>
Cloud-based log exportation software<br>
IDS software<br>

This is detailed below:

<h3>a. Port-Scanning Software (ports.py)</h3>
This application allows the user to scan for open or closed ports within a specified range, as well as check for ARP tables and banners therein. Specifically, the port scanner allows for three sorts of operations:

    1. Generating a config file for automated scanning;
    2. Reading said file in order to perform an automated scan;
    3. Performing a custom scan with specific user-provided parameters.
    
<h4>i. Generating a Config File for Automated Scanning</h4>
In the first instance, the user is presented with a series of options, which are then sent to a configuration file named, "config.txt". Please note that this filename **MUST** remain the same at all times; otherwise, Scoria will be unable to detect it.

The config file consists of the following parameters, listed in order of appearance:

    1. Host IP address
    2. Lower limit for port scan range
    3. Upper limit for port scan range
    4. ARP/Banner-grabbing option number for scan
        1 = Banners only;
        2 = ARP only;
        3 = ARP/Banners;
        4 = No additional checks
        
Again, the formatting for config.txt **MUST** follow the above, four-line format, otherwise Scoria will be unable to read it properly. Furthermore, config.txt **MUST** be located in the same folder as the rest of the software, otherwise Scoria will be unable to detect it.
 
<h4>ii. Reading a Config File for Automated Scanning</h4>
If the second option is followed, Scoria will attempt to locate config.txt in the Scoria installation directory. If successful, it will then attempt to run an automated scan based on the parameters found therein.

<h4>iii. Performing a Custom Scan</h4>
The third option allows the user to manually stipulate parameters with which to scan the host system. This is useful if a one-time scan on specific ports, or for particular ARP table entries or banners, is needed. It works largely the same way as Option 1 does, save for the fact that no information is piped to config.txt.

<h3>b. Live-Input Packet Sniffer (netmon.py, sniffer.py, linput.py)</h3>
This application allows a user to sniff for network packets and filter for custom characteristics. For instance, if a user wanted to only output TCP packets with the destination IP 10.20.30.4, the syntax would be: 

<code>sudo ./sniffer.py -dest 10.20.30.4 -pr TCP</code>

This allows for a constant and uninterrupted workflow, and with the --sleep option, a user can pause output after each packet for an easier to follow output.

The Live input functionality is performed via linput.py. As sniffer.py is running, a user may send brand new arguments for filtering to the output. If sniffer is output packets that filter for source IP 30.40.50.6, and during this output a user decides to filter for source IP 20.40.60.8 instead, the run this command in the newly opened terminal:

<code>./linput.py -s 20.40.60.8</code>

sniffer.py would read this new filter instruction and print accordingly


<h3>c. Cloud-Based Log Exportation Software (s3nder.sh, cloudlog.py)</h3>
In order to use the clould logging functionality you will need to have set up an aws account and create an IAM user. Here is a great guide to get you started - https://aws.amazon.com/getting-started/hands-on/backup-to-s3-cli/. 

<h4>i. Sending Logs to S3</h4>
S3nder.sh asks the user to input the full path of the location of the files they would like to send. Once the path is given, they are asked to enter their aws credentials and the name of the bucket they would like to store this information in. If successful, the program echoes “Credentials saved successfully” and “logs sent to S3!”. 

<h4>i. Deleting Logs & Accessing Logs</h4>
Once the logs are sent, program asks the user if they would like to remove the logs that have been sent. If yes, the user inputs the path to the logs, and the program confirms if the user is positive of their choice; it then deletes the files. To access your logs, log into your aws account anc go to the S3 service to view your buckets and logs.

<h3>d. IDS Software (netids.py)</h3>
This is a Host IDS feature that is designed for the network environment of the host computer. It utilizes a combination of signature-based and anomaly-based detection methods. 


<h2>3. Important Information Regarding Live-Input</h2>

In order to perform live-input packet-sniffing, initiate the necessary script by running:<br>
<code>>>> linput.py</code><br>
In the new user terminal window which Scoria starts up, with any necessary arguments in the usual syntax.
