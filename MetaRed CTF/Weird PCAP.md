misc
## Analysis
We started by analyzing the provided capture file `weird.pcap`.
A protocol hierarchy check (`tshark -z io,phs`) revealed significant DNS traffic.

Inspecting the DNS queries specifically:
```bash
tshark -r weird.pcap -Y dns -T fields -e dns.qry.name
```

We observed a series of suspicious reverse DNS lookup (PTR) queries in the format `<IP>.in-addr.arpa`:

```
85.78.76.80.in-addr.arpa
123.67.48.118.in-addr.arpa
51.114.84.95.in-addr.arpa
95.99.104.52.in-addr.arpa
110.78.101.124.in-addr.arpa
95.85.115.49.in-addr.arpa
110.103.95.68.in-addr.arpa
78.83.33.33.in-addr.arpa
125.192.180.219.in-addr.arpa
```

## Decoding
The "IP addresses" being queried appeared to be carriers for the flag data rather than legitimate network addresses. We extracted the octets from the IPs and converted them to ASCII.

For example, the first IP `85.78.76.80`:
- 85 -> U
- 78 -> N
- 76 -> L
- 80 -> P

Proceeding with the full list:
1. 85.78.76.80     -> UNLP
2. 123.67.48.118   -> {C0v
3. 51.114.84.95    -> 3rT_
4. 95.99.104.52    -> _ch4
5. 110.78.101.124  -> nNe|
6. 95.85.115.49    -> _Us1
7. 110.103.95.68   -> ng_D
8. 78.83.33.33     -> NS!!
9. 125...          -> } (plus padding/noise)

## Flag
Concatenating the decoded segments reveals the flag:

`UNLP{C0v3rT__ch4nNe|_Us1ng_DNS!!}`