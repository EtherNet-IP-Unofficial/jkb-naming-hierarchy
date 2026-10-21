Use lab/CakePlant.py

This script emulates a hierarchical factory network on a single linux machine using IP Namespaces (ip netns) and Virtual Ethernet (veth) cables.

Requires:

- linux
- sudo
- ip
- sysctl
- unshare
- mount
- ping
- dig
- tsig-keygen
- nsupdate
- named
- kea-dhcp6
- kea-dhcp-ddns
- radvd
- lldpd
- avahi-daemon
- dhclient
- odhcp6c (this needs to be built from sources https://github.com/openwrt/odhcp6c) and the binary needs to be put in CWD where you invoke CakePlant.py

If you don't stop CakePlant.py, it will clean up after itself.

You can stop the script mid-flight and check communication using wireshark (ip netns exec <namespace-name> wireshark)
