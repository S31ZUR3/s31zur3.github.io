forensics

1.  **Initial Reconnaissance:** I started by examining the provided files, `nullctf.pcapng` and `README.md`. The `README.md` was empty.

2.  **Pcapng Analysis with tshark:** I identified `nullctf.pcapng` as a packet capture file. Initial `tshark` commands (`tshark -r nullctf.pcapng | head -n 10`) showed USB traffic.
    `tshark -r nullctf.pcapng -q -z conv,usb` revealed significant data transfer on USB device address 5 (endpoints 1.5.1 and 1.5.4), indicating potential HID (Human Interface Device) or mass storage activity.

3.  **Troubleshooting tshark Data Extraction:** Multiple attempts to extract raw data or specific fields using `tshark` (e.g., `usb.capdata`, `usb.hid.data`, `-x`, `-T json`) to various output files consistently resulted in empty files, despite the `pcapng` being 13MB in size. This suggested an issue with `tshark`'s file output or a specific nuance of this `pcapng` file that prevented standard extraction.

4.  **Identifying the Data Type:** Given the USB traffic and large data volume, it was highly probable that the flag was hidden within HID keyboard input (scancodes).

5.  **Scapy for USB HID Decoding:** Since `tshark` was problematic for extraction, I decided to use `scapy`, a powerful Python packet manipulation library.
    *   I first checked for `scapy` installation (`python3 -c "import scapy.all"`), which showed it was not installed.
    *   I installed `scapy` using `pip install scapy`.

6.  **Python Script Development:** I developed a Python script (`extract_usb_hid.py`) to:
    *   Load the `nullctf.pcapng` file using `scapy.all.rdpcap`.
    *   Iterate through packets, filtering for `USBpcap` layers that also contained a `Raw` layer (indicating data).
    *   Heuristically identified 8-byte `Raw` payloads as potential HID keyboard reports.
    *   Parsed the modifier byte (byte 0) and scancode byte (byte 2) from these reports.
    *   Implemented a `scancode_map` to convert USB HID scancodes to ASCII characters, handling both unshifted and shifted key presses.

7.  **Script Debugging:**
    *   Initially, the script had a `SyntaxError` due to an unescaped backslash in the `scancode_map`, which was corrected.                                                                 *   Next, `ImportError: cannot import name 'USBPcap' from 'scapy.all'` occurred. I corrected the import to `from scapy.layers.usb import USBPcap`.
    *   Another `ImportError` revealed a case sensitivity issue: the correct import was `from scapy.layers.usb import USBpcap` (lowercase 'p'), which was then also applied to `packet.haslayer(USBpcap)`.
8.  **Flag Extraction:** After correcting the Python script, executing `python3 extract_usb_hid.py nullctf.pcapng` successfully outputted a string. The first part of the output clearly resembled a flag format: `nullctf{4nd_7h47s_h0w_4_k3yl0gg3r_w0rks}`. The remaining characters were likely noise from imperfect scancode mapping or other key events not directly relevant to the flag.

The flag is: `nullctf{4nd_7h47s_h0w_4_k3yl0gg3r_w0rks}`