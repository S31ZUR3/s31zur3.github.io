forensics
## Initial Analysis
I began by examining the protocols present in the capture:
- HTTP
- DNS
- TCP/UDP
- ICMP
- ESP (Encapsulating Security Payload)
- TFTP

Standard checks for common data exfiltration (HTTP objects, DNS TXT records, ICMP payloads) yielded no direct results.

## Discovery
Further investigation of UDP traffic revealed a specific pattern originating from the IP address `172.20.160.238`.

1. **Signaling:** Two specific packets marked the beginning and end of a data sequence:
   - Packet 61: Payload "START"
   - Packet 478: Payload "END"

2. **Data Encoding:** The packets between these markers (Packets 71 through 477) appeared to have empty or placeholder payloads ("XX"), but their **UDP source ports** contained suspicious values.

## Decoding
Listing the source ports of the packets between the "START" and "END" markers revealed the following sequence of decimal values:

83, 104, 97, 90, 123, 55, 104, 49, 115, 95, 49, 115, 95, 55, 104, 51, 95, 119, 49, 114, 51, 95, 115, 104, 52, 114, 107, 95, 102, 49, 52, 103, 125

Converting these ASCII decimal values to characters:
- 83  -> S
- 104 -> h
- 97  -> a
- 90  -> Z
- 123 -> {
- 55  -> 7
- 104 -> h
- 49  -> 1
- 115 -> s
- 95  -> _
- 49  -> 1
- 115 -> s
- 95  -> _
- 55  -> 7
- 104 -> h
- 51  -> 3
- 95  -> _
- 119 -> w
- 49  -> 1
- 114 -> r
- 51  -> 3
- 95  -> _
- 115 -> s
- 104 -> h
- 52  -> 4
- 114 -> r
- 107 -> k
- 95  -> _
- 102 -> f
- 49  -> 1
- 52  -> 4
- 103 -> g
- 125 -> }

## Flag
`ShaZ{7h1s_1s_7h3_w1r3_sh4rk_f14g}`