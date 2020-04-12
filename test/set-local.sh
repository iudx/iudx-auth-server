#!/bin/sh

echo "lookup file bind"    		>  /etc/resolv.conf
echo "nameserver 1.1.1.1"		>> /etc/resolv.conf

echo "1. start /etc/hosts file is ---"
cat /etc/hosts
echo "1. end   /etc/hosts file is ---"

echo "127.0.0.1	auth.iudx.org.in"	>> /etc/hosts
echo "127.0.0.1	iisc.iudx.org.in"	>> /etc/hosts
echo "127.0.0.1	localhost"		>> /etc/hosts
echo "::1	localhost"		>> /etc/hosts

echo "2. start /etc/hosts file is ---"
cat /etc/hosts
echo "2. end   /etc/hosts file is ---"
