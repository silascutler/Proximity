#!/usr/bin/perl
#############################################################################################
#
#__________                     .__        .__  __
#\______   \_______  _______  __|__| _____ |__|/  |_ ___.__.
# |     ___/\_  __ \/  _ \  \/  /  |/     \|  \   __<   |  |
# |    |     |  | \(  <_> >    <|  |  Y Y  \  ||  |  \___  |
# |____|     |__|   \____/__/\_ \__|__|_|  /__||__|  / ____|
#                              \/        \/          \/
#
# proximity_server
#
# Copyright (C) 2013, Silas Cutler
#      <Silas.Cutler@BlackListThisDomain.com>
#
# This program is free software; you can redistribute it and/or modify it without restriction.
#      Any implimentation or profitting from this code requires the consent of the original 
#      author.  Any updates or impovements are not required to be shared with the author, but 
#      encoraged.  
#
# This software is provided as is.  The author or any associated parties are not liable for 
#      any use of this software or any damage that may occur from this software.
#
#############################################################################################
#	v0.8
#############################################################################################


use strict;
use warnings;
use DBI;

require 'etc/config.pm';

our $database_name;
our $database_user;
our $database_password;

our $dbh = DBI->connect('dbi:mysql:'. $database_name,$database_user,$database_password) or die "Connection Error: $DBI::errstr\n";
$dbh->{mysql_auto_reconnect} = 1;



our $sth_infected = $dbh->prepare('INSERT INTO filter_matches 
										(source_ip, destination_port, filter_id, timestamp, pcap_file, count) 
										VALUES ( ? , ? , ? , ? , ?, 1) ON DUPLICATE KEY UPDATE count=count+1');

our $sth_connection = $dbh->prepare('INSERT INTO connection_log 
										(source_ip, protocol, destination_port, pcap_file, timestamp, count) 
										VALUES ( ? , ? , ? , ? , ? , ?) ON DUPLICATE KEY UPDATE count=count + ?');

our $sth_http_hosts = $dbh->prepare('INSERT INTO http_hosts 
										(hostname, source_ip, destination_port, pcap_file, timestamp, count) VALUES ( ? , ? , ? ,  ? , ?, 1) ON DUPLICATE KEY UPDATE count=count + 1');
										
our $sth_dns_request = $dbh->prepare('INSERT INTO dns_lookups 
										(source_ip, query, record_type, returned, timestamp, count) VALUES ( ? , ? , ? ,  ? , ?, ?) ON DUPLICATE KEY UPDATE count=count + 1');

our $sth_proc_pcap = $dbh->prepare('INSERT INTO pcap_stats 
										( pcap_file, pcap_processed_time) VALUES ( ? , ? )');

our $sth_proc_dns = $dbh->prepare('INSERT INTO dns_log_stats 
										( dns_file, dns_processed_time) VALUES ( ? , ? )');


















return 1;


