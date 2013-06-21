

Proximity
=========

Sinkhole Operational Framework for Automation and Reporting




Overview
--------

#### Files

 * proximity_core : The Core of the Proximity Framework
 * proximity_controller : Tool for interfacing with the database (Add, Remove, List Filters)
 * proximity_reporter : Generate Reports, Pull Data, Search the DataBase
 * proximity_anomaly : Generate Anomaly Report Emails
 * proximity_config : Configuration File
 * proximity_initdb : Create the database scheme (and wipe it)

#### Setup
The setup is really up to the user.  Generally, what I have found to be the best method is one server with a public IP which collects data and one that does the processing.  The data from the collecting server gets rsynced off to the other.  I've attached under ~/misc some of the modified system files.  I use snort for capturing because of the build in packet logging.  TCPDump / NGREP / TCPFlow / etc. all work as well. 

#### Installation
 1. Install System Packages, Modules, and Software
 2. Configure `proximity_config` with needed details
 3. Execute `proximity_initdb` Please note that you *DO NOT* need to pre-configure your Database and User. This will do that for you. Just make sure you set the right values in the config before running this script.




Required Software
-----------------

#### System Packages
	sudo apt-get install build-essential zlib1g-dev libpcap-dev
	sudo perl MCPAN -e 'install Proc::ProcessTable'

#### Perl Modules 
	sudo perl -MCPAN -e 'install DBI,Authen::SASL,MIME::Lite,Getopt::Long,Net::Pcap,NetPacket::Ethernet,NetPacket::IP,NetPacket::TCP,NetPacket::UDP,Config::Simple,IO::Socket::INET,PerlIO::gzip,Time::Local,Proc::Daemon'

#### Software
	ngrep (Will be removed in next version...hopefully)




Mailing List
------------
https://oid.tisf.net/mailman/listinfo/proximity
