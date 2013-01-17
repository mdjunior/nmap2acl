#!/usr/bin/perl

use warnings;

use Nmap::Parser;
use Switch;

my $np = new Nmap::Parser;
my $type = $ARGV[0];
my $infile = $ARGV[1];


#GETTING SCAN INFORMATION
$np->parsefile($infile);

#DETECTING FIREWALL TYPE
switch ($type) {
	case "cisco"	{ $coment="!"; $mask="permit tcp host %s any eq %s\n"; $prefix="\n";}
	case "pf"	{ $coment="#"; $mask="pass quick on \$ext_if proto tcp from any to %s port %s\n"; 
			  $prefix = "# This is an example of firewall configuration. It should be changed to meet your needs.
# Configuration of interfaces
ext_if=COMPLETE HERE
int_if=COMPLETE HERE

set skip on lo

# Blocks everything on the external interface (below the nmap2acl allow legitimate traffic)
block in on \$ext_if all
block out on \$ext_if all

# No blocks on the internal interface
pass in on \$int_if all
pass out on \$int_if all\n\n";}

	case "iptables"	{ $coment="#"; $mask="iptables -A INPUT -p tcp -s %s --sport %s -j ACCEPT\n";
			  $prefix = "iptables -F

# Skip conectons established and related
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Setting policy to DROP by default (below the nmap2acl allow legitimate traffic)
iptables -A INPUT -p tcp -j DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP\n\n";}
	else		{ $coment="!"; $mask="permit tcp host %s any eq %s\n"; $prefix="\n"; }
    }

printf ("%s",$prefix);
for my $host ($np->all_hosts()){
    for my $port ($host->tcp_ports()){
        my $service = $host->tcp_service($port);
        my $os = $host->os_sig;
        # imprime o servico tambem
	#print "permit tcp host ".$host->ipv4_addr()." any eq ".$port."|".$service->name."\n";
        #print "permit tcp host ".$host->ipv4_addr()." any eq ".$port."\n";
        printf($mask,$host->ipv4_addr(),$port);
	}
}



