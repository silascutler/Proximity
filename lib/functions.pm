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
use Net::Pcap;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;
use NetPacket::UDP;
use IO::Socket::INET;
use PerlIO::gzip;
use Time::Local;

require 'etc/config.pm';

my $err;


#Enable functionality & Paths
our ($proc_pcap_proc_enabled, $proc_pcap_path);
our ($proc_dns_proc_enabled, $proc_dns_path);
our ($user_pcap_path, $user_dns_path);

#Sinkhole Attributes
our ($var_sinkhole_address);

#Database Functions & DB Connection
our ($dbh, $sth_infected, $sth_connection, $sth_http_hosts, $sth_dns_request, $sth_proc_pcap, $sth_proc_dns);

our ($search_recent, $count_only, $report, $pcap_limiter, $uniq_hosts, $print_asn, $email, $search_pcap, $list_unmatched, $sender_address, $email_from);

our ( $mail_From_Address, $mail_From_Address_Password, $mail_Mail_Server, $mail_Mail_Server_Port, $mail_report_address );

our ($add_filter,$dis_filter, $list_filter,$enable_filter, $list_filter_dis );


our ( %raw_pcap_files, %raw_dns_logs, %tcp_pcap_filters, %udp_pcap_filters, $process);

sub intro_clear_screen {
       print "\n" x 200;
       print '
__________                     .__        .__  __
\______   \_______  _______  __|__| _____ |__|/  |_ ___.__.
 |     ___/\_  __ \/  _ \  \/  /  |/     \|  \   __<   |  |
 |    |     |  | \(  <_> >    <|  |  Y Y  \  ||  |  \___  |
 |____|     |__|   \____/__/\_ \__|__|_|  /__||__|  / ____|
                              \/        \/          \/

Proximity - Sinkhole Automation and Filtering System

';
        print "\n" x 20;
}

sub usage_server {
        print "Proximity - proximity-reporter 0.7 \n";
        print "usage: ./$0
        		-import-pcap     (-ip )     <PATH>     - process pcap files from specific path
        		-import-dns      (-id )     <PATH>     - process dns logs from specific path
        		-help            (-?  )     You are here
";
        exit;
}

sub usage_reporter{
        print "Proximity - proximity-reporter 1.0 \n - Silas Cutler 2012\n\n";
        print "usage: ./$0
        
------------ Infection Search ------------------------
-search-filter                ( -sf   )       - Search for filter matches based on Filter ID
-search-filter-notes          ( -sfn  )       - Search for filter matches based on Filter Notes
-search-filter-asn            ( -sfa  )       - Search for filter matches based on ASN Number
-search-filter-asn-name       ( -sfan )       - Search for filter matches based on ASN Name

-count                        ( -c    )       - Only print counts (skip Address Listing)
-search-recent                ( -r    )       - Only print Results from the past 24
-print-asn                    ( -pa   )       - Print ASN Name
-pcap_limit                   ( -pl   )       - Print only hosts that have been seen in more the X PCAP files
-uniq_hosts                   ( -ul   )       - Filter all hosts that have been seen with more then 1 HTTP host
		
------------ Connection Search ------------------------
-search-conn-asn              ( -sca  )       - Search for Connections based on ASN Number
-search-conn-asn-name         ( -scan )       - Search for Connections based on ASN Name

-count                        ( -c    )       - Only print counts (skip Address Listing)
-search-recent                ( -r    )       - Only print Results from the past 24 hours
-print-asn                    ( -pa   )       - Print ASN Name

------------ Hosts Search ----------------------------
-search-hostname             ( -sh    )      - Search for IP addresses by Host Name 
-search-hostname-all         ( -sha   )      - Search for IP addresses by Host Name and Subdomains    
-search-hostname-only        ( -sho   )      - Search for hostnames by string    

-count                        ( -c    )      - Only print counts (skip Address Listing)
-search-recent                ( -r    )      - Only print Results from the past 24 hours
-print-asn                    ( -pa   )      - Print ASN Name
-pcap_limit                   ( -pl   )       - Print only hosts that have been seen in more the X PCAP files
-uniq_hosts                   ( -ul   )       - Filter all hosts that have been seen with more then 1 HTTP host


------------ IP Searches -----------------------------
-ip-pcap                      ( -pcap	)     - Search for PCAPs that contain an IP address

------------ List Information ------------------------
-list-recent-connections
-list-recent-infections

-print-asn                    ( -pa   )       - Print ASN Name
	
------------ IP Group Information -------------------
-list-scanners                ( -ls   )       - List all IP addresses that attempted to check for 
-list-unmatched               ( -lu   )       - List any regular connecting IP that did not match a filter or scanner conditions		
-print-asn                    ( -pa   )       - Print ASN Name

------------ System Information ---------------------
-proc-stat                    ( -ps   )       - Processing Status	(All Time)
-filter-status                ( -fs   )       - Print Filters Status			       
-search-recent                ( -r    )       - Only print Results from the past 24 hours


-help                         ( -h    )       - Prints this Help Message
";
        exit;
}



### Load PCAP Files from a directory
sub load_pcap_files{
        my $count = 0;
        if (defined( $user_pcap_path )) {
	        $proc_pcap_path = $user_pcap_path;
	        $process = "false";
	    }
	    
        foreach(<$proc_pcap_path/*>){

                $raw_pcap_files{$_}++;
                $count++;
        }
        #print " [+] Loaded $count PCAP Files\n";
        return 0;
        
}
### Load DNS Files from a directory
sub load_dns_files{
        my $count = 0;
        if (defined( $user_dns_path )) {
	        $proc_dns_path = $user_dns_path;
	        $process = "false";
	    }
	    
        foreach(<$proc_dns_path/*>){
                $raw_dns_logs{$_}++;
                $count++;
        }
        #print " [+] Loaded $count DNS Logs\n";
        return 0;
        
}
### Load Checks to see if PCAP file has been processed.  If so, return 1 and stop processing
sub dns_log_files_handler{
	my $dns_log = shift;
	my $dns_log_ref = pull_dns_log_list(); # Pulls list of all PCAP Files
	if (grep {$dns_log eq $_ } @{$dns_log_ref}) {
		return 1;
	}
	else{
		return 0;
	}
		
#	exit;
}
sub update_filters_handler{
	my $pcap = shift;
	my $pcap_list_ref = pull_pcap_list(); # Pulls list of all PCAP Files
	if (grep {$pcap eq $_ } @{$pcap_list_ref}) {
		return 1;
	}
	else{
		update_filters();
		return 0;
	}
		
#	exit;
}
#### Pull list of Pcaps processed
sub pull_pcap_list{
	my @daily_pcaps = ();
	my $pcap_file = "";
	my $sql = 'SELECT pcap_file from pcap_stats ';
    my $request_handle = $dbh->prepare($sql);
    $request_handle->execute();
    $request_handle->bind_columns(undef, \$pcap_file );
    while($request_handle->fetch()){
    	push(@daily_pcaps,$pcap_file);
    }
    return \@daily_pcaps;
}
sub pull_dns_log_list{
	my @daily_logs = ();
	my $log_file = "";
	my $sql = 'SELECT dns_file from dns_log_stats ';
    my $request_handle = $dbh->prepare($sql);
    $request_handle->execute();
    $request_handle->bind_columns(undef, \$log_file );
    while($request_handle->fetch()){
    	push(@daily_logs,$log_file);
    }
    return \@daily_logs;
}

#Resets the filters that are currently in %pcap_filters
sub update_filters{
	my ($filter_id, $filter_protocol, $filter_port, $filter_pcre);
	
	%tcp_pcap_filters = ();
	%udp_pcap_filters = ();
	
	my $request_handle = $dbh->prepare('SELECT filter_id, filter_protocol,  filter_port, filter_pcre from filters where filter_status = "active"');
	$request_handle->execute();
	$request_handle->bind_columns(undef, \$filter_id, \$filter_protocol, \$filter_port, \$filter_pcre );
	while($request_handle->fetch()){
		if ($filter_protocol eq "tcp"){
			$tcp_pcap_filters{$filter_port}{$filter_pcre} = $filter_id;
		}
		elsif ($filter_protocol eq "udp"){
			$udp_pcap_filters{$filter_port}{$filter_pcre} = $filter_id;
		}
		else{
			# /This shouldn't happen
		}
	}
}

sub pcap_search{
	my $ip_address = shift;
	my $pcap_file = "";
	my %pcap_file_all = ();

	my $sql = 'select pcap_file from connection_log where ( source_ip = ? )';

    my $request_handle = $dbh->prepare($sql);
    	
    $request_handle->execute($ip_address);
    $request_handle->bind_columns(undef, \$pcap_file );
    while($request_handle->fetch()){
    	$pcap_file_all{$pcap_file}++;
    }
    return \%pcap_file_all;    	
}

sub process_filters_tcp{
        my $packet = shift;
        my $data = shift;
        my $proc_pcap_path = shift;
        my $timestamp = shift;

        if (my ($matched) = grep {$data->{data} =~ /($_)/is } keys %{$tcp_pcap_filters{"0"}} ) {
				add_filter_match($packet->{src_ip}, $data->{dest_port}, $tcp_pcap_filters{"0"}{$matched}, $proc_pcap_path,$timestamp);
		}

		if (my ($matched) = grep {$data->{data} =~ /($_)/is } keys %{$tcp_pcap_filters{$data->{dest_port}}} ) {
				add_filter_match($packet->{src_ip}, $data->{dest_port},  $tcp_pcap_filters{$data->{dest_port}}{$matched}, $proc_pcap_path, $timestamp);
		}
		if ($data->{data} =~ /Host:[\.]*\s*([A-Za-z0-9\-\_\.]*\.[A-Za-z\.\-\_0-9]*)*\s*[\.]*/i){
			return 0 if (!defined($1));
			my $host = $1;
			if ($host =~ /[A-Za-z0-9]/){
				add_seen_host($host, $packet->{src_ip}, $data->{dest_port}, $proc_pcap_path, $timestamp);
			}
		}
		return 0;
}
sub process_filters_udp{
        my $packet = shift;
        my $data = shift;
        my $proc_pcap_path = shift;
        my $timestamp = shift;
        if (my ($matched) = grep {$data->{data} =~ /($_)/is } keys %{$udp_pcap_filters{"0"}} ) {
				add_filter_match($packet->{src_ip}, $data->{dest_port}, $udp_pcap_filters{"0"}{$matched}, $proc_pcap_path, $timestamp);
		}

		if (my ($matched) = grep {$data->{data} =~ /($_)/is } keys %{$udp_pcap_filters{$data->{dest_port}}} ) {
				add_filter_match($packet->{src_ip}, $data->{dest_port},  $udp_pcap_filters{$data->{dest_port}}{$matched}, $proc_pcap_path, $timestamp);
		}
		if ($data->{data} =~ /Host:[\.]*\s*([A-Za-z0-9\-\_\.]*\.[A-Za-z\.\-\_0-9]*)*\s*[\.]*/i){
			return 0 if (!defined($1));
			my $host = $1;
			if ($host =~ /[A-Za-z0-9]/){
				add_seen_host($host, $packet->{src_ip}, $data->{dest_port}, $proc_pcap_path, $timestamp);
			}
		}
		return 0;
}

sub pcap_handler{
    my @src_vict = ();
    my @src_scnr = ();
    my %act_ports = ();
    my %packet_data = ();
    my %pcapHeader = ();
    
    

    my $proc_pcap_path = shift;

    my $cont = update_filters_handler($proc_pcap_path);
    if ($cont == 1){ 
    #	print " [X] Stop!! $proc_pcap_path \n";
    	return; 
    }
	mark_pcap_processed($proc_pcap_path);

    print " [+] Starting on PCAP - $proc_pcap_path\n";
    eval{
		my $pcap_handler = Net::Pcap::pcap_open_offline("$proc_pcap_path", \$err) or die "Can't read pcap file!: $err\n";	
	    while (my $pkt = Net::Pcap::next($pcap_handler, \%pcapHeader)){
	    	my $timestamp = $pcapHeader{tv_sec};
	    	
	            my $eth=NetPacket::Ethernet->decode($pkt);
	            if($eth->{type} == 2048){
	                    my $ip=NetPacket::IP->decode($eth->{data});
	                    if ($ip->{src_ip} eq $var_sinkhole_address){ next; }
	                    if( $ip->{proto} == 6 ){
	                        my $tcp=NetPacket::TCP->decode($ip->{data});
	                        $packet_data{$ip->{src_ip}}{"tcp"}{$tcp->{dest_port}}{$timestamp}++;
	                        process_filters_tcp($ip,$tcp,$proc_pcap_path, $timestamp);
	                    }elsif ( $ip->{proto} == 17 ){
	                         my $udp = NetPacket::UDP->decode($ip->{data});
	                        $packet_data{$ip->{src_ip}}{"udp"}{$udp->{dest_port}}{$timestamp}++;
	                        process_filters_tcp($ip,$udp,$proc_pcap_path, $timestamp);
	                        
	                    }
	                    
	            }

	    }
	    
	    foreach my $source_IP (keys %packet_data){
	        foreach my $dest_port (keys $packet_data{$source_IP}){
	        	foreach my $conn_protocol (keys $packet_data{$source_IP}{$dest_port}){
		        	foreach my $pcap_time (keys ${$packet_data{$source_IP}{$dest_port}}{$conn_protocol} ){
			        	add_connection($proc_pcap_path, $source_IP,$dest_port,$conn_protocol, $pcap_time, ${${$packet_data{$source_IP}{$dest_port}}{$conn_protocol}}{$pcap_time});
		        	}		        	
		        }
	        }
	    }

	    print " [+] Finished $proc_pcap_path\n";
	    update_asn_details($proc_pcap_path);
	    Net::Pcap::close($pcap_handler);
    };
    if ($@) {
    	print " [X] Problem Processing $proc_pcap_path \n";
		return 1;
	}
}

sub dns_handler{
	my $dns_log_file = shift;
	my %month_lookup = ( Jan => 0, Feb => 1, Mar => 2, Apr => 3, May => 4, Jun => 5, Jul => 6, Aug => 7, Sep => 8, Oct => 9, Nov => 10, Dec => 11 );

    my $cont = dns_log_files_handler($dns_log_file);
    if ($cont == 1){ 
    #	print " [X] Stop!! $dns_log_file \n";
    	return; 
    }
    print " [+] Starting on DNS Log - $dns_log_file\n";
	mark_dns_log_processed($dns_log_file);


	open (FILE, "<:gzip", "$dns_log_file");
	
	while (<FILE>){
		eval{	
			my $raw_dns_request = $_;
			$raw_dns_request =~ s/(\r|\n)*//sg;
			my @tmp_dns_request = 
				$raw_dns_request 
					=~ m/([0-9\-]*\-[A-Za-z\-]*\-[0-9\-]*\s[0-9\-]*\:[0-9\-]*\:[0-9\-]*\.[0-9\-]*)\squeries:\sinfo:\sclient\s([0-9\-\.]*\x23[0-9]*):\squery:\s([A-Za-z0-9\.\-\_*]*)\sIN([A-Za-z]*)\s.*\(([0-9\-\.]*)\)/;
					
			unless ( 
				(defined($tmp_dns_request[0])) 
					&& (defined($tmp_dns_request[1]))
					&& (defined($tmp_dns_request[2]))
					&& (defined($tmp_dns_request[3]))
					&& (defined($tmp_dns_request[4]))
				){
					print "Bad line in DNS Logs\n";
					print "$_\n";
					next;
				}
			my @norm_timestamp = $tmp_dns_request[0] =~ m/([0-9\-]*)\-([A-Za-z\-]*)\-([0-9\-]*)\s([0-9\-]*)\:([0-9\-]*)\:([0-9\-]*)\.([0-9\-]*)/;
			my $time_stamp = timelocal( $norm_timestamp[5],$norm_timestamp[4], $norm_timestamp[3], $norm_timestamp[0], $month_lookup{$norm_timestamp[1]}, $norm_timestamp[2] );
			
		#	print "Source_IP = " .$tmp_dns_request[1] . " | Query = "     .$tmp_dns_request[2] . " | Timestamp $time_stamp\n";
			
			add_dns_request($tmp_dns_request[1], $tmp_dns_request[2], $tmp_dns_request[3], $tmp_dns_request[4], $time_stamp );
			
			

		};
		if (@$) {
			print "ERROR with \n$_\n";
		}
	}
	print " [+] Finished $dns_log_file\n";
	
	close FILE;
	
}


sub add_filter_match {
	my $source_ip = shift;
	my $infected_ip_port = shift; 
	my $filter_id = shift;
	my $pcap_file = shift;
	my $timestamp = shift;
	eval{
		$sth_infected->execute($source_ip, $infected_ip_port, $filter_id, $timestamp, $pcap_file,);
		$sth_infected->finish;
	};
	if ($@) {
		return 1;
	}
		return 0;
}

sub add_connection {
	my $pcap_file = shift;
	my $source_ip = shift;
	my $destination_port = shift;
	my $protocol = shift;
	my $timestamp = shift;
	my $occurances = shift;

	eval{
		$sth_connection->execute($source_ip, $destination_port, $protocol,  $pcap_file,$timestamp, $occurances,$occurances);
		$sth_connection->finish;
	};
	if ($@) {
		print " [X] Failed to Add Connection entry\n";
		return 1;
	}
	return 0;
}

sub add_dns_request {
	my $source_ip = shift;
	my $query = shift;
	my $record_type = shift;
	my $returned = shift;
	my $timestamp = shift;

	eval{
		$sth_dns_request->execute($source_ip, $query, $record_type, $returned, $timestamp, 1);
		$sth_dns_request->finish;
	};
	if ($@) {
		print " [X] Failed to Add Connection entry\n";
		return 1;
	}
	return 0;
}

sub mark_pcap_processed {
	my $pcap_file = shift;
	my $timestamp = time;	
	if (defined($user_pcap_path)){ print "Not adding timestamp\n"; $timestamp = 0;}
	
	eval{
		$sth_proc_pcap->execute($pcap_file,$timestamp);
		$sth_proc_pcap->finish;
	};
	if ($@) {
		print " [X] Failed to Add PCAP Processed entry\n";
		return 1;
	}
	return 0;
}

sub mark_dns_log_processed {
	my $dns_log_file = shift;
	my $timestamp = time;
	if (defined($user_dns_path)){ print "Not adding timestamp\n"; $timestamp = 0;}
	
	eval{
		$sth_proc_dns->execute($dns_log_file,$timestamp);
		$sth_proc_dns->finish;
	};
	if ($@) {
		print " [X] Failed to Add PCAP Processed entry\n";
		return 1;
	}
	return 0;
}


sub update_asn_details{
	my $pcap_file = shift;
	my ($ip_address);
	my $bulk_query = "begin\n";
	my $request_handle = $dbh->prepare('SELECT DISTINCT source_ip from connection_log where (asn is null and asn_name is null and pcap_file = ?)');
	$request_handle->execute($pcap_file);
	$request_handle->bind_columns(undef, \$ip_address);
	
	while($request_handle->fetch()){
		$bulk_query .= "$ip_address\n";
	}
	$bulk_query .= "end\n";
	
	my $socket;
	$socket = new IO::Socket::INET (
		PeerAddr   => 'whois.cymru.com:43',
		Proto      => 'tcp'
		) or die "ERROR in Socket Creation : $!\n";
	$socket->send($bulk_query);	
		
	my $query_result = "";
	while (<$socket>){
		$query_result .= $_;
	}
	print " [+] Data received from socket\n";
	$socket->close();
	add_asn_details($query_result, $pcap_file);
	return 0;
}


sub pull_ips_needing_asn{

}

sub add_asn_details{
	my @query_results = split(/\n/, shift );
	my $pcap_file = shift;
	foreach (@query_results){
		my @asn_record = split(/\s*\|\s*/, $_ );
		my ($asn, $asn_name, $source_ip) = (" ", " ", " ");
		$asn = $asn_record[0] if (defined($asn_record[0])); 
		$asn_name = $asn_record[2] if (defined($asn_record[2]));
		$source_ip = $asn_record[1] if (defined($asn_record[1]));
		
		eval{
			my $sth = $dbh->prepare('UPDATE connection_log set asn = ? , asn_name = ? WHERE (source_ip = ? and pcap_file = ?)');
			$sth->execute($asn, $asn_name, $source_ip, $pcap_file);
			$sth->finish;
		};
		if ($@) {
			print " [X] Error Updating ASN details\n";
			return 1;
		}

	}
	print " [+] ASN Details Updated successfully\n";
	return 0;
}

sub add_seen_host {
	my $host = shift;
	my $source_ip = shift;
	my $destination_port = shift;
	my $pcap_file = shift;
	my $timestamp = shift;

	eval{
		$sth_http_hosts->execute($host, $source_ip, $destination_port, $pcap_file, $timestamp );
		$sth_http_hosts->finish;
	};
	if ($@) {
		print " [X] Failed to Insert Host Entry (Details: $host, $source_ip, $pcap_file\n";
		return 1;
	}
	return 0;
}

sub pull_packet_raw{
	my $source_ip = shift;
	my $pcap_file_ref = pcap_search($source_ip);
	my %pcapHeader = ();
	my $output = "";
	my $payload = "";
	foreach my $pcap_file (@{$pcap_file_ref}){	
		unless ( -f $pcap_file) {
			$payload .= "Missing PCAP File - $pcap_file\n";
			next;
		}
	
#		my $pcap_handler = Net::Pcap::pcap_open_offline("$pcap_file", \$err) or die "Can't read pcap file!: $err\n";	
#		my $filter;
#		Net::Pcap::compile(  $pcap_handler,  \$filter, '(tcp[13] & 8 != 0)', 0, 0,) && die 'Unable to compile packet capture filter';
#		Net::Pcap::setfilter( $pcap_handler, $filter) && die 'Unable to set packet capture filter';
#
#		while (my $pkt = Net::Pcap::next($pcap_handler, \%pcapHeader)){		
#			my $eth=NetPacket::Ethernet->decode($pkt);
#			if($eth->{type} == 2048){
#				my $ip=NetPacket::IP->decode($eth->{data});
#				
#				if ($ip->{src_ip} ne $source_ip){ next; }
#				
#				if( $ip->{proto} == 6 ){
#					my $tcp=NetPacket::TCP->decode($ip->{data});
#					$payload = $ip->{data};
#					$payload =~ s/[\x00-\x09|\x0B-\x1F|\x7F-\xFF|\n|\r]/./g;
#					print "TCP $source_ip \n$payload\n-------------------------------\n" if ($debug == 1);
#					$payload .= "File = $pcap_file\n";
#
#					return $tcp->{dest_port}, "\n" . $payload . "\n";
#					
#				}elsif ( $ip->{proto} == 17 ){
#					my $udp = NetPacket::UDP->decode($ip->{data});
#					$payload = $ip->{data};
#					$payload =~ s/[\x00-\x09|\x0B-\x1F|\x7F-\xFF|\n|\r]/./g;
#					print "UDP $source_ip\n $payload\n-------------------------------\n" if ($debug == 1);
#					$payload .= "File = $pcap_file\n";
#					return $udp->{dest_port}, "\n" . $payload . "\n";
#				}       
#			}
#		}


            open( PROCESS , "ngrep -I $pcap_file host $source_ip -W single -q -n 1 |" ) or die "Failed to open tcpflow: $!";
                    while( <PROCESS> ) {
                            $output .= "$_\n";
                    #       print "$_\n";
                    }
            close PROCESS; 

		
		
		$output =~ s/^$//g;
		if ($output =~ /[A-Za-z0-9]/ ){
			return $output;
		}
	}
	
	print "Fail closed\n";
	return $output;
}


sub pull_recent_pcaps{
	my @daily_pcaps = ();
	my $pcap_file = "";
	
	my $sql = 'SELECT pcap_file from pcap_stats ';
	$sql .= 'where (pcap_processed_time > unix_timestamp(now()) - 86400)' if (defined($search_recent));
	
    my $request_handle = $dbh->prepare($sql);
    $request_handle->execute();
    $request_handle->bind_columns(undef, \$pcap_file );
    
    while($request_handle->fetch()){
    	push(@daily_pcaps,$pcap_file);
    }
    
    return \@daily_pcaps;
}





sub asn_lookup{	
	my $ip_address = shift;
	my $asn_name = "";

	my $sql = 'select asn_name from connection_log where (source_ip = ? and asn_name is not null) limit 1';
    my $request_handle = $dbh->prepare($sql);
    	
    $request_handle->execute($ip_address);
    $request_handle->bind_columns(undef, \$asn_name );
    $request_handle->fetch();

    if (!defined($asn_name)){
	    	return "NULL:";
    }
    return $asn_name;
}


### Search filter_matched table by filter_id field
sub search_filter_id_matched_hosts{	
	my $search = shift;
	my $matched_ip = "";
	my %matched_hosts = ();
	my $pcap_ref = pull_recent_pcaps();
	
	my $sql = 'select source_ip  
		from filter_matches 
		left join filters 
		on filter_matches.filter_id = filters.filter_id where ((filter_matches.filter_id = ?  )';
	$sql .= ' && ( filter_matches.pcap_file = "' . join('" || filter_matches.pcap_file="' , @{$pcap_ref}) . '"))';
    my $request_handle = $dbh->prepare($sql);
    	
    $request_handle->execute($search);
    $request_handle->bind_columns(undef, \$matched_ip );
    while($request_handle->fetch()){
    	my $asn_name = asn_lookup($matched_ip);
    	$matched_hosts{$matched_ip} = $asn_name;
    }
    return \%matched_hosts;
}

### Search filter_matched table by filter_notes field
sub search_filter_notes_matched_hosts{	
	my $search = shift;
	my $matched_ip = "";
	my %matched_hosts = ();
	my $pcap_ref = pull_recent_pcaps();
	
	my $sql = 'select source_ip 
		from filter_matches 
		left join filters 
		on filter_matches.filter_id = filters.filter_id where ((filters.filter_note like "' . $search . '%" )';
	$sql .= ' && ( filter_matches.pcap_file = "' . join('" || filter_matches.pcap_file="' , @{$pcap_ref}) . '"))';

    my $request_handle = $dbh->prepare($sql);
    	
    $request_handle->execute();
    $request_handle->bind_columns(undef, \$matched_ip );
    while($request_handle->fetch()){
    	my $asn_name = asn_lookup($matched_ip);
    	$matched_hosts{$matched_ip} = $asn_name;
    }
    return \%matched_hosts;
}
### Search filter_matched table by connection_log ASN number field
sub search_asn_number_matched_hosts{	
	my $search = shift;
	my $matched_ip = "";
	my %matched_hosts = ();
	my $pcap_ref = pull_recent_pcaps();
	
	my $sql = 'select filter_matches.source_ip  
		from filter_matches 
		left join connection_log 
		on filter_matches.source_ip = connection_log.source_ip where ((connection_log.asn = ?  )';
	$sql .= ' && ( connection_log.pcap_file = "' . join('" || connection_log.pcap_file="' , @{$pcap_ref}) . '"))';

    my $request_handle = $dbh->prepare($sql);
    	
    $request_handle->execute($search);
    $request_handle->bind_columns(undef, \$matched_ip );
    while($request_handle->fetch()){
    	my $asn_name = asn_lookup($matched_ip);
    	$matched_hosts{$matched_ip} = $asn_name;
    }
    return \%matched_hosts;
}
sub search_asn_name_matched_hosts{	
	my $search = shift;
	my $matched_ip = "";
	
	my %matched_hosts = ();
	my $pcap_ref = pull_recent_pcaps();
	
	my $sql = 'select filter_matches.source_ip  
		from filter_matches 
		left join connection_log 
		on filter_matches.source_ip = connection_log.source_ip where ((connection_log.asn_name like "%' . $search . '%"  )';
	$sql .= ' && ( filter_matches.pcap_file = "' . join('" || filter_matches.pcap_file="' , @{$pcap_ref}) . '"))';

    my $request_handle = $dbh->prepare($sql);
    	
    $request_handle->execute();
    $request_handle->bind_columns(undef, \$matched_ip );
    while($request_handle->fetch()){
    	my $asn_name = asn_lookup($matched_ip);
    	$matched_hosts{$matched_ip} = $asn_name;    
    }
    return \%matched_hosts;
}


sub search_connection_asn_number{	
	my $asn_number = shift;
	my $connection_ip = "";

	my %connections = ();
	my $pcap_ref = pull_recent_pcaps();

	my $sql = 'select source_ip from connection_log where ( ';
	$sql .= '( pcap_file = "' . join('" || pcap_file="' , @{$pcap_ref}) . '") && ';
	$sql .= '( asn = ? ))';

    my $request_handle = $dbh->prepare($sql);
    	
    $request_handle->execute($asn_number);
    $request_handle->bind_columns(undef, \$connection_ip );
    while($request_handle->fetch()){
    	my $asn_name = asn_lookup($connection_ip);
    	$connections{$connection_ip} = $asn_name;
    }
    return \%connections;    

}

sub search_connection_asn_name{	
	my $asn_name = shift;
	my $connection_ip = "";

	my %connections = ();
	my $pcap_ref = pull_recent_pcaps();

	my $sql = 'select source_ip from connection_log where ( ';
	$sql .= '( pcap_file = "' . join('" || pcap_file="' , @{$pcap_ref}) . '") && ';
	$sql .= '( asn_name like "%' . $asn_name . '%"))';

    my $request_handle = $dbh->prepare($sql);
    	
    $request_handle->execute();
    $request_handle->bind_columns(undef, \$connection_ip );
    while($request_handle->fetch()){
    	my $asn_name = asn_lookup($connection_ip);
    	$connections{$connection_ip} = $asn_name;
    }
    return \%connections;    

}


sub search_top_domains{	
	my $domain_name = "";
	my $count = "";
	my $index = 0;
	my %connections = ();
	my $pcap_ref = pull_recent_pcaps();

	my $sql = 'select hostname , count(source_ip) as total_count from http_hosts where (';
	$sql .= '( pcap_file = "' . join('" || pcap_file="' , @{$pcap_ref}) . '")) ';
	$sql .= ' group by hostname order by total_count desc limit 15';

    my $request_handle = $dbh->prepare($sql);
    $request_handle->execute();
    $request_handle->bind_columns(undef, \$domain_name , \$count);
    while($request_handle->fetch()){
    	$connections{$index}{$domain_name} = $count;
    	$index++;
    }
    return \%connections;    

}

sub search_top_ports{	
	my $port = "";
	my $count = "";
	my $index = 0;
	my %connections = ();
	my $pcap_ref = pull_recent_pcaps();

	my $sql = 'select destination_port , count(source_ip) as total_count from connection_log where (';
	$sql .= '( pcap_file = "' . join('" || pcap_file="' , @{$pcap_ref}) . '")) ';
	$sql .= ' group by destination_port order by total_count desc limit 15';

    my $request_handle = $dbh->prepare($sql);
    $request_handle->execute();
    $request_handle->bind_columns(undef, \$port , \$count);
    while($request_handle->fetch()){
    	$connections{$index}{$port} = $count;
    	$index++;
    }
    return \%connections;    

}

sub search_asn_summary{	
	my ($unmatched_ip, $ports , $count, $asn_name) = ();

	my %connections = ();
	my $pcap_ref = pull_recent_pcaps();
	
	my $sql = 'SELECT source_ip, count(destination_port) as occurance, sum(count) as counter 
					FROM connection_log WHERE ';
		$sql .= '( pcap_file = "' . join('" || pcap_file="' , @{$pcap_ref}) . '") ';
		$sql .= 'GROUP BY source_ip';

    my $request_handle = $dbh->prepare($sql);
    	
    $request_handle->execute();
    $request_handle->bind_columns(undef, \$unmatched_ip, \$ports ,\$count);
    while($request_handle->fetch()){
    	my $asn_name = asn_lookup($unmatched_ip);
    	$connections{$asn_name}{$unmatched_ip}=$count if ( ($ports < 4) && ($count > 500) && ($asn_name =~ /\w/));
    }
    return \%connections;   



}

sub search_host_names{	
	my $search = shift;
	my $source_ip = ();

	my %connections = ();
	my $pcap_ref = pull_recent_pcaps();
	
	my $sql = 'SELECT source_ip FROM http_hosts WHERE (( hostname = "' . $search . '") &&';
		$sql .= '( pcap_file = "' . join('" || pcap_file="' , @{$pcap_ref}) . '") )';
		$sql .= 'GROUP BY source_ip';

    my $request_handle = $dbh->prepare($sql);
    	
    $request_handle->execute();
    $request_handle->bind_columns(undef, \$source_ip );
    while($request_handle->fetch()){
    	my $asn_name = asn_lookup($source_ip);
    	$connections{$source_ip} = $asn_name;
    }
    return \%connections;   
}

sub search_host_names_by_ip{	
	my $search = shift;
	my $source_ip = ();

	my %connections = ();
	my $pcap_ref = pull_recent_pcaps();
	
	my $sql = 'SELECT hostname FROM http_hosts WHERE (( source_ip = "' . $search . '") &&';
		$sql .= '( pcap_file = "' . join('" || pcap_file="' , @{$pcap_ref}) . '") )';
		$sql .= 'GROUP BY hostname';

    my $request_handle = $dbh->prepare($sql);
    	
    $request_handle->execute();
    $request_handle->bind_columns(undef, \$source_ip );
    while($request_handle->fetch()){
    	my $asn_name = asn_lookup($source_ip);
    	$connections{$source_ip} = $asn_name;
    }
    return \%connections;   
}

sub search_host_names_rough{	
	my $search = shift;
	my $source_ip = ();

	my %connections = ();
	my $pcap_ref = pull_recent_pcaps();
	
	my $sql = 'SELECT source_ip FROM http_hosts WHERE (( hostname like "%' . $search . '%") &&';
		$sql .= '( pcap_file = "' . join('" || pcap_file="' , @{$pcap_ref}) . '") )';
		$sql .= 'GROUP BY source_ip';

    my $request_handle = $dbh->prepare($sql);
    	
    $request_handle->execute();
    $request_handle->bind_columns(undef, \$source_ip );
    while($request_handle->fetch()){
    	my $asn_name = asn_lookup($source_ip);
    	$connections{$source_ip} = $asn_name;
    }
    return \%connections;   
}

sub search_host_names_only{	
	my $search = shift;
	my $source_ip = ();

	my %connections = ();
	my $pcap_ref = pull_recent_pcaps();
	
	my $sql = 'SELECT hostname FROM http_hosts WHERE (( hostname like "%' . $search . '%") &&';
		$sql .= '( pcap_file = "' . join('" || pcap_file="' , @{$pcap_ref}) . '") )';
		$sql .= 'GROUP BY hostname';

    my $request_handle = $dbh->prepare($sql);
    	
    $request_handle->execute();
    $request_handle->bind_columns(undef, \$source_ip );
    while($request_handle->fetch()){
    	$connections{$source_ip}++;
    }
    return \%connections;   
}


sub search_print{
	my $search_ref = shift;
	my $description = shift;
	my $count = 0;
	$description .= " ( From the past 24 hours ) " if (defined($search_recent));
	
	print "$description: \n";
	$report .="$description: \n" if (defined($email));
	
	if (!defined($count_only)){	
		foreach( keys %{$search_ref} ){
			if (defined($pcap_limiter)){
				my $pcap_count = pcap_search($_);
				next if (keys (%{$pcap_count}) <= $pcap_limiter);
			}
			if (defined($uniq_hosts)){
				my $hosts_count = search_host_names_by_ip($_);
				next if (keys (%{$hosts_count}) > 1 );

			}
			
			
			if (defined($print_asn)){
				print " - $_  ( ${$search_ref}{$_} )\n";
				$report .= " - $_  ( ${$search_ref}{$_} )\n" if (defined($email));
			} else{
				print " - $_\n";
				$report .= " - $_\n" if (defined($email));
			}
			$count++;
		}
	}
	 
	print "Total -- " . $count . "\n";
	$report .= "Total -- " . $count . "\n" if (defined($email));
}


sub search_unique_ports{	
	my $dst_port = "";

	my %ports = ();
	my $pcap_ref = pull_recent_pcaps();

	my $sql = 'select distinct destination_port from connection_log where ( ';
	$sql .= '( pcap_file = "' . join('" || pcap_file="' , @{$pcap_ref}) . '"))';

    my $request_handle = $dbh->prepare($sql);
    	
    $request_handle->execute();
    $request_handle->bind_columns(undef, \$dst_port );
    while($request_handle->fetch()){
    	$ports{$dst_port}++;
    }
    return \%ports;    

}

sub search_unique_ip_adresses{	
	my $source_ip = "";
	my $occurance = "";
	my %connections = ();
	my $index = 0 ;
	my $pcap_ref = pull_recent_pcaps();
	
	my $sql = 'select source_ip, sum(count) as occ from connection_log where ( ';
	$sql .= '( pcap_file = "' . join('" || pcap_file="' , @{$pcap_ref}) . '")) ';
	$sql .= ' group by source_ip order by occ desc';

    my $request_handle = $dbh->prepare($sql);
    	
    $request_handle->execute();
    $request_handle->bind_columns(undef, \$source_ip, \$occurance);
    while($request_handle->fetch()){
    	$connections{$index}{$source_ip} = $occurance;
    	$index++;
    }
    return \%connections;    

}

sub search_scanner{	
	my $scanner_ip 	= "";
	my $occurance 	= "";
	
	my %connections = ();
	my $pcap_ref = pull_recent_pcaps();
	
	my $sql = 'SELECT source_ip, count(destination_port) as occurance from connection_log where ';
	$sql .= '( pcap_file = "' . join('" || pcap_file="' , @{$pcap_ref}) . '")';
	$sql .= '  group by source_ip order by occurance';

    my $request_handle = $dbh->prepare($sql);
    	
    $request_handle->execute();
    $request_handle->bind_columns(undef, \$scanner_ip, \$occurance );
    while($request_handle->fetch()){
    	my $asn_name = asn_lookup($scanner_ip);
    	$connections{$scanner_ip} = $occurance if ($occurance > 4);
    }
    
    
    return \%connections;    

}

sub scanner_search_print{
	my $scanner_ref = shift();
	
	print "Scanner Hosts: (Hosts which hit more than 4 ports) \n";
	$report .="Scanner Hosts: (Hosts which hit more than 4 ports) \n" if (defined($email));
	
	if (!defined($count_only)){	
		foreach( keys %{$scanner_ref} ){
			print " - $_ \n";	
			$report .= " - $_\n" if (defined($email));
		} 
	}
	print "Total -- " . keys (%{$scanner_ref}) . "\n";
	$report .= "Total -- " . keys (%{$scanner_ref}) . "\n" if (defined($email));
	$report .="\n" if (defined($email));

}

sub search_unmatched{	
	my ($unmatched_ip, $ports , $count ) = ();

	my %connections = ();
	my $pcap_ref = pull_recent_pcaps();
	
	my $sql = 'SELECT connection_log.source_ip , count(connection_log.destination_port) as occurance, sum(connection_log.count) as counter 
					FROM connection_log 
					LEFT JOIN filter_matches 
					ON connection_log.source_ip = filter_matches.source_ip 
					WHERE (filter_matches.source_ip IS null &&';
		$sql .= '( connection_log.pcap_file = "' . join('" || connection_log.pcap_file="' , @{$pcap_ref}) . '"))';
		$sql .= 'GROUP BY source_ip';

    my $request_handle = $dbh->prepare($sql);
    	
    $request_handle->execute();
    $request_handle->bind_columns(undef, \$unmatched_ip, \$ports ,\$count);
    while($request_handle->fetch()){
    	my $asn_name = asn_lookup($unmatched_ip);
    	$connections{$unmatched_ip}=$asn_name if ( ($ports < 4) && ($count > 30) );
    }
    return \%connections;    

}


sub search_unmatched_anomaly{	
	my ($unmatched_ip ) = "";

	my %connections = ();
	my $pcap_ref = pull_recent_pcaps();
	
	my $sql = 'SELECT connection_log.source_ip
					FROM connection_log 
					LEFT JOIN filter_matches 
					ON connection_log.source_ip = filter_matches.source_ip 
					WHERE (filter_matches.source_ip IS null &&';
		$sql .= '( connection_log.pcap_file = "' . join('" || connection_log.pcap_file="' , @{$pcap_ref}) . '"))';
		$sql .= 'GROUP BY source_ip ';

    my $request_handle = $dbh->prepare($sql);
    	
    $request_handle->execute();
    $request_handle->bind_columns(undef, \$unmatched_ip);
    while($request_handle->fetch()){
    	
    	my (%ports , %pcap, $port, $pcap_file, $count) = ();
    	my $t_count = 0;
		my $details_request_handle = $dbh->prepare("SELECT destination_port, pcap_file, count from connection_log where source_ip = ? ");
			
		$details_request_handle->execute($unmatched_ip);
		$details_request_handle->bind_columns(undef, \$port, \$pcap_file, \$count);
		while($details_request_handle->fetch()){    	
    		$ports{$port}++;
    		$pcap{$pcap_file}++;
    		$t_count += $count;
    	}
    	
		my $asn_name = asn_lookup($unmatched_ip);
#		print "$unmatched_ip " . keys(%ports) . " $t_count ". keys(%pcap) . "\n";
		$connections{$unmatched_ip}=$asn_name if ( (  keys (%ports) <= 2 ) && ( $t_count > 5 ) && ( keys (%pcap) > 1 ) );
    	
    }
    return \%connections;    

}


sub unmatched_search_print{
	my $scanner_ref = shift();
	
	print "Unmatched Hosts: (Hosts which did not match a filter and not classify as a scanner)  \n";
	$report .="Unmatched Hosts: (Hosts which did not match a filter and not classify as a scanner)  \n" if (defined($email));

	if (!defined($count_only)){	
		foreach( keys %{$scanner_ref} ){
		
			print " - $_\n";	
			$report .= " - $_\n" if (defined($email));
		} 
	}
	print "Total -- " . keys (%{$scanner_ref}) . "\n";
	$report .= "Total -- " . keys (%{$scanner_ref}) . "\n" if (defined($email));
	$report .="\n" if (defined($email));

}

sub filter_count {
	my $count = 0;
	my $filter_id = shift;
	
	my %connections = ();
	my $pcap_ref = pull_recent_pcaps();
	
	my $sql = 'select count(distinct source_ip) from filter_matches
					WHERE (filter_id = ? && ';
		$sql .= '( pcap_file = "' . join('" ||pcap_file="' , @{$pcap_ref}) . '"))';

    my $request_handle = $dbh->prepare($sql);
    	
    $request_handle->execute($filter_id);
    $request_handle->bind_columns(undef, \$count);
    $request_handle->fetch();
    return $count;   
	
}

sub pcap_search_print{
	my $pcap_ref = shift();
	
	print "Pcap Files with $search_pcap: \n";
	$report .= "Pcap Files with $$search_pcap: \n" if (defined($email));
	foreach( keys %{$pcap_ref} ){
		print " - $_\n";
		$report .= " - $_\n" if (defined($email));
	} 
	print "Total -- " . keys (%{$pcap_ref}) . "\n";
	$report .= "Total -- " . keys (%{$pcap_ref}) . "\n" if (defined($email));
	$report .="\n" if (defined($email));

}

sub print_pcap_stats{
	my %output = ();
	if (defined($search_recent)){
		print "Sinkhole Statistics from the past 24 hours:\n\n";
		$report .= "Sinkhole Statistics from the past 24 hours:\n\n" if (defined($email));
	}else{
		print "Sinkhole Statistics:\n\n";
		$report .= "Sinkhole Statistics:\n\n"  if (defined($email));
	}

	
	my $daily_pcaps = pull_recent_pcaps();
	print " - [*] Processed ". $#{$daily_pcaps} . " files\n"; 
	$report .= " - [*] Processed ". $#{$daily_pcaps} . " files\n" if (defined($email));
	
	my $connections_ref = search_connection_asn_name("");
    print " - [*] ". keys (%{$connections_ref}) . " Inbound Connections\n";
    $report .= " - [*] ". keys (%{$connections_ref}) . " Inbound Connections\n" if (defined($email));
    
    my $uniq_ports = search_unique_ports();
    print " - [*] ". keys (%{$uniq_ports}) . " Unique Ports\n";
    $report .= " - [*] ". keys (%{$uniq_ports}) . " Unique Ports\n" if (defined($email));
    
    my $uniq_addresses = search_unique_ip_adresses();
    print " - [*] ". keys (%{$uniq_addresses}) . " Unique IP Addresses\n";
    $report .= " - [*] ". keys (%{$uniq_addresses}) . " Unique IP Addresses\n" if (defined($email));

	if (!defined($list_unmatched)){	
		my $unmatched_addresses = search_unmatched();
		print " - [*] ". keys (%{$unmatched_addresses}) . " Unmatched IP Addresses\n";
		$report .= " - [*] ". keys (%{$unmatched_addresses}) . " Unmatched IP Addresses\n" if (defined($email));
	}
	
	
	print "\nTop 15 Talkers ( IP / Count):\n";
	$report .= "\nTop 15 Talkers ( IP / Count):\n";
	my $top_talkers = search_unique_ip_adresses();
	foreach my $index_key ( sort { $a <=> $b }  keys %{$top_talkers} ) {
		foreach my $source_ip (keys %{${$top_talkers}{$index_key}} ){
				print "$source_ip (" . ${${$top_talkers}{$index_key}}{$source_ip} . ")\n";
				$report .= "$source_ip (" . ${${$top_talkers}{$index_key}}{$source_ip} . ")\n" if (defined($email));
			
		}
		
		if ($index_key == 15 ){	 last;	}
		
	}	
	
	
	print "\nTop 15 Hostnames from HTTP Requests ( Domain Name / Count):\n";
	$report .= "\nTop 15 Hostnames from HTTP Requests ( Domain Name / Count):\n";

	my $top_talker_domains = search_top_domains();	
	foreach my $index_key ( sort { $a <=> $b }  keys %{$top_talker_domains} ) {
		foreach my $domain_name (keys %{${$top_talker_domains}{$index_key}} ){
				print "$domain_name (" . ${${$top_talker_domains}{$index_key}}{$domain_name} . ")\n";
				$report .= "$domain_name (" . ${${$top_talker_domains}{$index_key}}{$domain_name} . ")\n" if (defined($email));

		}
		
		if ($index_key == 15 ){	 last;	}
		
	}		
   
	print "\nTop 15 Ports from Inbound Requests ( Domain Name / Count):\n";
	$report .= "\nTop 15 Ports from Inbound Requests ( Domain Name / Count):\n";

	my $top_conn_ports = search_top_ports();	
	foreach my $index_key ( sort { $a <=> $b }  keys %{$top_conn_ports} ) {
		foreach my $port_number (keys %{${$top_conn_ports}{$index_key}} ){
				print "$port_number (" . ${${$top_conn_ports}{$index_key}}{$port_number} . ")\n";
				$report .= "$port_number (" . ${${$top_conn_ports}{$index_key}}{$port_number} . ")\n" if (defined($email));

		}
		
		if ($index_key == 15 ){	 last;	}
		
	}
 
	print "\n";
	$report .="\n" if (defined($email));
	
}

sub print_filter_stats{

	my ($filter_id, $filter_note) = "";

	print "\nFilter Counts\n";
	$report .= "\nTop 15 Talkers ( IP / Count):\n";
	
	
	my $sql = 'select filter_id, filter_note from filters where filter_status = "active";';
    my $request_handle = $dbh->prepare($sql);
    	
    $request_handle->execute();
    $request_handle->bind_columns(undef, \$filter_id, \$filter_note );
    while($request_handle->fetch()){
    	my $filter_count = filter_count($filter_id);
    	print " [$filter_id] $filter_note ( $filter_count )\n";	
    	$report .= " [$filter_id] $filter_note ( $filter_count )\n";	
    }

	print "\n";
	$report .="\n" if (defined($email));
	
	
}


## Email Alering
sub reporter_email_report{
	my $date = `date +%Y-%m-%d --date="1 days ago"`;
	chomp($date);
	$report =~ s/\n/\n/g;
    my $output ="";
    my $from = $mail_From_Address;
    
    my @to = (shift);
    my $subject= "Proximity Sinkhole Status Report ( $date ) DEV";

    if (defined($email_from)){
		$from	 = $email_from;  
	}

    my $message = qq{
Proximity Sinkhole Status Report for $date  
$report

	};

	my $asn_summary_ref = search_asn_summary();
	$message .= "\nRepeated Connection Attempts by ASN [Total: " . keys ( %{$asn_summary_ref} ) . "] ( ASN / Count):\n";

	foreach my $key ( sort keys %{$asn_summary_ref} ) {
			$message .= " - $key  (IP Count - " . keys ( ${$asn_summary_ref}{$key} ) . ")\n";
	}    
    $message .= "\n\n\n";
    MIME::Lite->send('smtp',$mail_Mail_Server . ':' . $mail_Mail_Server_Port ,AuthUser=>$mail_From_Address, AuthPass=>$mail_From_Address_Password);
    foreach my $recipient(@to){
            my $msg = MIME::Lite->new(
                    From     => $from,
                    To       => $recipient,
                    Subject  => $subject,
                    Data     => $message,
					Type	 => 'Text/text',
            );

            
            #if (defined($count_only)){	
				
				## Filter Matched IPs
				print "Attaching All IPs\n";
				my $uniq_ip_addresses = "All Inbound IP addresses connecting to Sinkhole ([Packet Count] IP / (ASN) ) \n" . "-"x20 . "\n";
				my $ip_ref = search_unique_ip_adresses();
				foreach my $index_key ( sort { $a <=> $b }  keys %{$ip_ref} ) {
					foreach my $source_ip (keys %{${$ip_ref}{$index_key}} ){
					    	my $asn_name = asn_lookup($source_ip);

							$uniq_ip_addresses .= "[${${$ip_ref}{$index_key}}{$source_ip}] $source_ip ( $asn_name  )\n";


					}							
				}	
				

            	
            	$msg->attach (
				Type => 'Text/Text',
				Filename => 'uniq_ips.txt',
				Data => $uniq_ip_addresses,
				Disposition => 'attachment'
				) or die "Error adding the text message part: $!\n";
				
            #}
            $msg->send or die "Message Send Faied";
            print "Email Sent - $subject /$recipient !\n";
    }
}


sub add_filter{

	
	print "Enter Port this activity on:\n";
	my $filter_port = <>;
	chomp($filter_port);
	if ($filter_port !~ /^[0-9]*$/ ){
		$filter_port= 0;
	}
	
	print "Enter Protocol for this activity (tcp / udp) :\n";
	my $filter_protocol = <>;
	chomp($filter_protocol);
	$filter_protocol = lc($filter_protocol);

	if ( ( $filter_protocol ne "tcp") && ($filter_protocol ne "udp") ){
		print "Must be either UDP or TCP\n";
		exit;
	}
	
	print "Enter PCRE Filter Below:\n";
	my $filter_pcre = <>;
	chomp($filter_pcre);
	
	print "Your PCRE is: \"$filter_pcre\"\n";
	my $filter_pcre_test = eval { qr/$filter_pcre/ };
	if ($@){
		print "Invalid Regex\n";
		exit;
	}

	print "Enter any notes:\n";
	my $filter_notes = <>;
	chomp($filter_notes);


		#Submit Query
		my $sth = $dbh->prepare("INSERT INTO filters (filter_port, filter_protocol, filter_pcre, filter_note, filter_status, added) VALUES  ( ?, ?, ?, ?, 'active', ?)");
		$sth->execute( $filter_port, $filter_protocol, $filter_pcre, $filter_notes, time );
		print "Filter Added - Port: $filter_port/$filter_protocol - /$filter_pcre/ \n";



}

sub list_filters_active{
        my ($filter_note, $filter_port, $filter_pcre, $filter_id);
        my $count = 0;

        my $request_handle = $dbh->prepare('SELECT filter_id, filter_port, filter_pcre, filter_note from filters where filter_status = "active" order by filter_id');
        $request_handle->execute();
        $request_handle->bind_columns(undef, \$filter_id, \$filter_port, \$filter_pcre ,\$filter_note);
        while($request_handle->fetch()){
            $count++;
            print "\n [$filter_id] - Port: $filter_port\n - PCRE: /$filter_pcre/\n - Note: - $filter_note\n";
        }
        print "\n Total = $count\n";
}

sub list_filters_disabled{
        my ($filter_note, $filter_port, $filter_pcre, $filter_id);
        my $count = 0;

        my $request_handle = $dbh->prepare('SELECT filter_id, filter_port, filter_pcre, filter_note from filters where filter_status = "disable" order by filter_id');
        $request_handle->execute();
        $request_handle->bind_columns(undef, \$filter_id, \$filter_port, \$filter_pcre ,\$filter_note);
        while($request_handle->fetch()){
            $count++;
            print "\n [$filter_id] - Port: $filter_port\n - PCRE: /$filter_pcre/\n - Note: - $filter_note\n";
        }
        print "\n Total = $count\n";
}

sub disable_filter{

        my ($filter_note, $filter_port, $filter_pcre, $filter_id);
        my $count = 0;

        my $request_handle = $dbh->prepare('SELECT filter_id, filter_port, filter_pcre, filter_note from filters where filter_status = "active" order by filter_id');
        $request_handle->execute();
        $request_handle->bind_columns(undef, \$filter_id, \$filter_port, \$filter_pcre ,\$filter_note);
        while($request_handle->fetch()){
            $count++;
            print "\n [$filter_id] - Port: $filter_port\n - PCRE: /$filter_pcre/\n - Note: - $filter_note\n";
        }

		print "Enter  Filter ID Number:\n";
		my $filter_number = <>;
		chomp($filter_number);
		if ($filter_number !~ /^[0-9]*$/){
			print "Enter Filter Number only!\n";
			exit;
		}
		my $sth = $dbh->prepare("UPDATE filters set filter_status = 'disable' WHERE ( filter_id = ?  )");
		$sth->execute($filter_number);
		print "Disabled Filter - $filter_number\n";
		
}

sub enable_filter{

        my ($filter_note, $filter_port, $filter_pcre, $filter_id);
        my $count = 0;

        my $request_handle = $dbh->prepare('SELECT filter_id, filter_port, filter_pcre, filter_note from filters where filter_status = "disable" order by filter_id');
        $request_handle->execute();
        $request_handle->bind_columns(undef, \$filter_id, \$filter_port, \$filter_pcre ,\$filter_note);
        while($request_handle->fetch()){
            $count++;
            print "\n [$filter_id] - Port: $filter_port\n - PCRE: /$filter_pcre/\n - Note: - $filter_note\n";
        }

		print "Enter  Filter ID Number:\n";
		my $filter_number = <>;
		chomp($filter_number);
		if ($filter_number !~ /^[0-9]*$/){
			print "Enter Filter Number only!\n";
			exit;
		}
		my $sth = $dbh->prepare("UPDATE filters set filter_status = 'enable' WHERE ( filter_id = ?  )");
		$sth->execute($filter_number);
		print "Enabled Filter - $filter_number\n";
		
}








return 1;
