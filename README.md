nmap2acl
========

nmap2acl is a tool that makes the parser results of an nmap scan and turn into different types of rules for firewalls. Its function is to make the control of the network perimeter efficiently and less costly.

Use cases
---------

The use of this tool is recommended for very large networks where the access-checking process will begin, and existing access can not be stopped.

Therefore, since the access can not be interrupted, the tool generates rules that allow access while the security team checks the necessity and compliance with the rules.

Installation and use
--------------------

You can use the tool through the following steps:

1 - Install dependencies

    cpan Nmap::Parser


2 - Run your nmap scan

Example:

    nmap 10.0.0.0/8 -oX nmap_results


3 - Run nmap2acl and vizualize the data (for iptables rules)

    ./nmap2acl.pl -t iptables -i nmap_results.xml


4 - Save results

    ./nmap2acl.pl -t iptables -i nmap_results.xml >> iptables.rules

