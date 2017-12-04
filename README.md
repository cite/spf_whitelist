# spf\_whitelist

This simple ruby script is used to generate a CIDR map
usable for e.g. the Postfix MTA to except large email
providers from things like blacklist checks.

It the amount of whitelist entries differ more than 10%,
a warning is issued and the new file is not written. In
that case, call the script again with "-f".

NOTE: This is by no means secure, a single changed line
from e.g. 127.16.0.0./12 to e.g. 172.12.0.0/12 would
no count towards the diff, but make a HUGE difference.


## Dependencies

* [dnsruby](https://github.com/alexdalitz/dnsruby) gem
* [ipaddress](https://github.com/ipaddress-gem/ipaddress) gem


# TODO

* read whitelist domains from file
* make change threshold configurable
