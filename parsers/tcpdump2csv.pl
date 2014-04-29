#! /usr/bin/perl


# tcpdump2csv.pl
# version 1.0
#
# Copyright (C) 2014 Rajesh Somasundaran <rajesh.somasundaran@sjsu.edu>
#
# This program is written towards the partial implementation of the project titled
# "Network Monitoring and Security Visualization" for CMPE-295B at 
# Department of Computer Engineering, San Jose State University
# Program: Master of Science in Computer Engineering
#

# This program takes as input the tcpdump pcat file and extracts the following fileds 
# to generate a .csv file:
#  Date & Time
#  Source IP address
#  Source port number
#  Destination IP address
#  Destination port number
#  Protocol
#  Length
#
# This data in the .csv file can be used for plotting various graphs and charts for 
# security virtualization.
# The output is delimited by TABs and can be read using any application such as 
# Microsoft Excel to read the data.
#
# Usage: 
#  $ tcpdump -n -r <your pcap file> | ./tcpdump2csv.pl > <your file>.csv
#
# Example:
#  $ tcpdump -n -r /tmp/tcpdump.pcap | ./tcpdump2csv.pl > tcpdump.csv
#
# Known limitations:
#  This program doesn't read lines for ARP, IP6, LLDP or blank lines. All of them are skipped
#  This program also skips all flags except the length
#

# One command line parameter, a filter which defines lines to include
$filter = shift;

print "Date\tSourceIP\tSourcePort\tDestIP\tDestPort\tProtocol\tLength\n";

while (my $line = <>) { # while there are lines to read

   next unless $line =~ m/$filter/;
   chomp $line;

   # The following regular expression extracts date, sourceIP, destIP, protocol and length
   # into variables $1-$5
   if ( $line =~ m/^([0-9:.]+)\s+IP\s+([0-9.]+)\s+\>\s+([0-9.]+):\s+([A-Za-z]+).*length\s+(\d+)$/ ) {
      ($date,$sourceIP,$targetIP,$proto,$length) = ($1,$2,$3,$4,$5);
      # Split the port number from IP address if present
      my ($sip1, $sip2, $sip3, $sip4, $sourcePort) = split (/\./, $sourceIP, 5);
      # rejoin remaining parts of IP address to forn a dotted quad IP address
      my $sip = "$sip1.$sip2.$sip3.$sip4";
      my ($dip1, $dip2, $dip3, $dip4, $destPort) = split (/\./, $targetIP, 5);
      my $dip = "$dip1.$dip2.$dip3.$dip4";
      
      # Write the extracted fields to the output
      print "$date\t$sip\t$sourcePort\t$dip\t$destPort\t$proto\t$length\n";

      # Skip 'Flags' protocol
      next if $proto eq 'Flags';
   } else { 
      # Skip all lines that are not in the form of the above regex
      next;
      #print "$line\n";
   }
}


1;  

