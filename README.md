

Proximity
=========

Sinkhole Operational Framework for Automation and Reporting



Required Software
-----------------

### System Packages
	sudo apt-get install build-essential zlib1g-dev libpcap-dev
	sudo perl MCPAN -e 'install Proc::ProcessTable'

### Perl Modules 
	sudo perl -MCPAN -e 'install DBI,Authen::SASL,MIME::Lite,Getopt::Long,Net::Pcap,NetPacket::Ethernet,NetPacket::IP,NetPacket::TCP,NetPacket::UDP,Config::Simple,IO::Socket::INET,PerlIO::gzip,Time::Local,Proc::Daemon'

### Software
	ngrep (Will be removed in next version...hopefully)



Overview
--------

### Files

The Core of the Proximity Framework
`proximity_core`

Tool for interfacing with the database (Add, Remove, List Filters)
`proximity_controller`

Generate Reports, Pull Data, Search the DataBase
`proximity_reporter`

Generate Anomaly Report Emails
`proximity_anomaly`

Configuration File
`proximity_config`

Create the database scheme (and wipe it)
`proximity_initdb`


### Setup
The setup is really up to the user.  Generally, what I have found to be the best method is one server with a public IP which collects data and one that does the processing.  The data from the collecting server gets rsynced off to the other.  I've attached under ~/misc some of the modified system files.  I use snort for capturing because of the build in packet logging.  TCPDump / NGREP / TCPFlow / etc. all work as well. 

### Installation
 1. Install System Packages, Modules, and Software
 2. Configure `proximity_config` with needed details
 3. Execute `proximity_initdb`



Mailing List
------------
https://oid.tisf.net/mailman/listinfo/proximity
