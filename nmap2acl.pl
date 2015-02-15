#!/usr/bin/perl

use strict;
use warnings;

#no warnings qw(experimental);
use feature ':5.10';

use Carp;
use Getopt::Long;
use Nmap::Parser;

our $VERSION = 1.0;

my $infile = qw{ };
my $type   = qw{ };

GetOptions('input=s' => \$infile, 'type=s' => \$type,);

if (!defined $infile || !-r $infile || !defined $type) {
    croak 'Error in command line arguments';
}

my $np = Nmap::Parser->new;

#  GETTING SCAN INFORMATION
$np->parsefile($infile);

#  DETECTING FIREWALL TYPE
my $mask;
my $prefix;
my $comment;

given ($type) {
    when (/^cisco/smx) {
        $comment = "\nremark %s\n";
        $mask    = "permit tcp host %s any eq %s\n";
        $prefix  = "\n";
    }
    when (/^pf/smx) {
        $comment = "\n# %s\n";
        $mask    = "pass quick on \$ext_if proto tcp from any to %s port %s\n";
        $prefix  = "\n";
    }

    when (/^iptables/smx) {
        $comment = "\n# %s \n";
        $mask    = "iptables -A INPUT -p tcp -s %s --sport %s -j ACCEPT\n";
        $prefix  = "\n";
    }
}

printf '%s', $prefix;

for my $host ($np->all_hosts()) {
    printf $comment, $host->addr();

    for my $port ($host->tcp_ports()) {
        my $os = $host->os_sig;

        printf $mask, $host->ipv4_addr(), $port;
    }
}


