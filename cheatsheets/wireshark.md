# Wireshark Display Filters

## Basic navigation
* `ip.addr eq x.x.x.x` - all traffic for specific IP address.
* `ip.src eq x.x.x.x and ip.dst eq y.y.y.y` - all converstation between two IP address.
* `tcp.port eq 443 or udp.port eq 53` - Find HTTPS or DNS.

## Search user-name
* `kerberos.CNameString and !(kerberos.CNameString contains"$")` - search user-name without pc name.

## Search suspicious activity
* `tcp.flags.syn eq 1 and tcp.flags.ack eq 0` - Search **SYN-scan** (many same packets).
* `http.request.method == "POST"` - Search of traffic exchange (chance of exfiltration).
* `dns.flags.response == 1 && dns.queries.name contains "evil"` - Search suspicious domains.
* `frame contains "password"` - Search of not secured passwords.
* `frane contains "this program"` - Search malicious files.
