# IPSec-bruteforce-ban
This script parses log messages to find failed IPSec connections and adds to Firewall address list.
You'll need to add firewall rule to block connections from origins which are in address list.
E. g.: `/ip firewall raw
add action=drop chain=prerouting src-address-list=IPSEC`



**How to...**
1. Download [IPSec-bruteforce-ban.rsc]() on your mikrotik router `/tool fetch url="`.
2. Import script `/import IPSec-bruteforce-ban.rsc`.
3. Adjust scheduler permissions if required.


Inspired (taken and modified) from:
- https://forum.mikrotik.com/t/black-list-for-failed-login-to-ipsec-vpn/130090/68
- https://github.com/mikrotik-user/IPSec-bruteforce-prevention
