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



our $proc_pcap_proc_enabled = 'true';
our $proc_pcap_path = '<PCAP PATH>';

our $proc_dns_proc_enabled = 'true';
our $proc_dns_path = '<DNS PATH>';


our $database_host = 'localhost';
our $database_name = '<DB NAME>';
our $database_user = '<DB USER>';
our $database_password = '<DB PASS>';


#This should be IP address will know itself by (=> the IP the sinkhole will be in PCAPs)
our $var_sinkhole_address = '<SINKHOLE IP>';

our $mail_From_Address = '<Sinkhole From Addrss@Domain.com>';
our $mail_From_Address_Password = '<Email password>';
our $mail_Mail_Server = '<MAIL SERVER>';
our $mail_Mail_Server_Port = '<MAIL PORT>';
our $mail_report_address = '<DESTINATION EMAIL>';



return 1;

