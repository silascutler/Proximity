

Proximity
=========

Sinkhole Operational Framework for Automation and Reporting

Required Software

Perl Modules 
[*] sudo perl -MCPAN -e 'install DBI,Authen::SASL,MIME::Lite,Getopt::Long,Net::Pcap,NetPacket::Ethernet,NetPacket::IP,NetPacket::TCP,NetPacket::UDP,Config::Simple,IO::Socket::INET,PerlIO::gzip,Time::Local,Proc::Daemon'

Software
[*] ngrep 





proximity_anomaly - Generates Anomaly Report Email <br />
proximity_config - Configuration File for Proximity<br />
proximity_controller - Tool for Adding / Removing / Listing Filters<br />
proximity_initdb - Creates Database scheme <br />
proximity_reporter - Generates reports / Pull data / Search<br />
proximity_server - Core <br />
<br />
<b>Installation</b>
 1. Install Modules & Software <br />
 2. Configure proximity_config with needed details <br />
 3. Execute proximity_initdb <br />