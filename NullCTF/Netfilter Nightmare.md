rev
## Challenge Overview
We were provided with a binary named `nightmare` and a packet capture file `traffic.pcap`. The premise is that the binary "messed up" the network traffic, specifically related to web browsing (DNS). The goal is to recover the visited websites/flag from the capture.

## Analysis

### Binary Analysis (`nightmare`)
1.  **Initial Inspection**: Using `file` and `strings`, we identified it as a 64-bit ELF executable dynamically linked with `libnetfilter_queue`. This library allows userspace programs to handle packets queued by the kernel packet filter.
2.  **Disassembly**: Disassembling the binary revealed the main loop handling packets.
    - It binds to a netfilter queue.
    - It processes UDP packets (specifically checking for port 53/DNS structure).
    - It iterates through the DNS query name.
3.  **Obfuscation Logic**: The assembly logic showed an XOR operation being applied to the payload.
    - The key for the XOR operation is 4 bytes long.
    - The key is derived dynamically from the packet headers:
        - Byte 0: UDP Source Port (Lower 8 bits)
        - Byte 1: UDP Source Port (Upper 8 bits)
        - Byte 2: DNS Transaction ID (Lower 8 bits)
        - Byte 3: DNS Transaction ID (Upper 8 bits)
    - The obfuscation is symmetric (XOR), so applying the same operation decrypts the data.

### PCAP Analysis (`traffic.pcap`)
The pcap file contained DNS traffic with unintelligible query names (e.g., hex strings or garbage characters). However, the UDP and DNS headers (Source Port and Transaction ID) were intact.

## Solution

To recover the original domains, we wrote a script to:
1.  Parse `traffic.pcap` using `tshark`.
2.  Extract the **UDP Source Port**, **DNS Transaction ID**, and the **Obfuscated Query Name** for each DNS packet.
3.  Reconstruct the 4-byte XOR key for each packet: `[SrcPort_Lo, SrcPort_Hi, TransID_Lo, TransID_Hi]`.
4.  XOR the bytes of the obfuscated query name with this key.

### Decrypted Output
Running the decryption script revealed several standard domains (google.com, github.com, etc.) and a series of specific domains that formed the flag:

1.  `nullctf{dns_.ro`
2.  `is_br0k3n_.ro`
3.  `why_is_i7.ro`
4.  `_4lw4ys_dns}.ro`

Combining these gives the final flag.

## Flag
`nullctf{dns_is_br0k3n_why_is_i7_4lw4ys_dns}`