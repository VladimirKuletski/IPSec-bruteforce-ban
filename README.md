# IPSec-bruteforce-ban
This script parses log messages to find failed IPSec connections and adds to Firewall address list.

Works on RouterOS 7.19.3

You'll need to add firewall rule to block connections from origins which are in address list.
Examples: 
`/ip firewall raw
add action=drop chain=prerouting src-address-list=IPSEC`
or
`/ip firewall filter
add action=drop chain=input comment="Stop bruteforce to IPsec services" \
    connection-state=new in-interface=<internet interface> src-address-list=IPSEC


**How to...**
1. Download [IPSec-bruteforce-ban.rsc](https://raw.githubusercontent.com/VladimirKuletski/IPSec-bruteforce-ban/refs/heads/main/IPSec-bruteforce-ban.rsc) on your mikrotik router `/tool fetch url=https://raw.githubusercontent.com/VladimirKuletski/IPSec-bruteforce-ban/refs/heads/main/IPSec-bruteforce-ban.rsc"`.
2. Import script `/import IPSec-bruteforce-ban.rsc`.
3. Adjust scheduler permissions if required.


Inspired (taken and modified) from:
- https://forum.mikrotik.com/t/black-list-for-failed-login-to-ipsec-vpn/130090/68
- https://github.com/mikrotik-user/IPSec-bruteforce-prevention
