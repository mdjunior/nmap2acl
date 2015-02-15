nmap2acl
========

nmap2acl is a tool that makes the parser results of an nmap scan and turn into different types of rules for firewalls. Its function is to make the control of the network perimeter efficiently and less costly.


You can use the tool through the following steps:


1 - Install dependencies

    cpan install NMAP::PARSER


2 - Run your nmap scan

Example:

    nmap 10.0.0.0/8 -oX nmap_results


3 - Run nmap2acl and vizualize the data

    perl nmap2acl.pl nmap_results.xml


4 - Save results

    perl nmap2acl.pl nmap_results.xml >> acl

