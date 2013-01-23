

Proximity
=========

Sinkhole Operational Framework for Automation and Reporting

Required Software

Perl Modules 
[*] sudo perl -MCPAN -e 'install DBI,Authen::SASL,MIME::Lite,Getopt::Long,Net::Pcap,NetPacket::Ethernet,NetPacket::IP,NetPacket::TCP,NetPacket::UDP,Config::Simple,IO::Socket::INET,PerlIO::gzip,Time::Local,Proc::Daemon'

Software
[*] ngrep (Will be removed in next version...hopefully)





proximity_anomaly - Generates Anomaly Report Email <br />
proximity_config - Configuration File for Proximity<br />
proximity_controller - Tool for Adding / Removing / Listing Filters<br />
proximity_initdb - Creates Database scheme <br />
proximity_reporter - Generates reports / Pull data / Search<br />
proximity_server - Core <br />
<br />
<b>Setup</b> <br />
The setup is really up to the user.  Generally, what I have found to be the best method is one server with a public IP which collects data and one that does the processing.  The data from the collecting server gets rsynced off to the other.  I've attached under ~/misc some of the modified system files.  I use snort for capturing because of the build in packet logging.  TCPDump / NGREP / TCPFlow / etc. all work as well. 

<b>Installation</b>
 1. Install Modules & Software <br />
 2. Configure proximity_config with needed details <br />
 3. Execute proximity_initdb <br />



Mailing List: https://oid.tisf.net/mailman/listinfo/proximity
