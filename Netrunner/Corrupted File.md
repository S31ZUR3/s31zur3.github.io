#Forensics 
### 1. File Identification
Initial inspection with the `file` command identified `ch13.bin` as generic "data".

```bash
$ file ch13.bin
ch13.bin: data
```

### 2. Hex Dump Analysis
Using `xxd` to examine the first few bytes of the file revealed a structure very similar to a PDF file, but with an unusual header:

```bash
$ xxd -l 128 ch13.bin
00000000: 2542 696e 2d31 2e36 0a25 f6e4 fcdf 0a35  %Bin-1.6.%.....5
00000010: 2030 206f 626a 0a3c 3c0a 2f4c 656e 6774   0 obj.<<./Lengt
00000020: 6820 3330 310a 2f46 696c 7465 7220 2f46  h 301./Filter /F
...
```

The header `%Bin-1.6` strongly suggested a modified PDF header, which should normally be `%PDF-1.6`. The rest of the file contained standard PDF markers like `obj`, `stream`, `endstream`, `endobj`, and `startxref`.

## Solution

### 1. Repairing the Header
The file was "corrupted" by replacing the `PDF` string in the header with `Bin`. To fix this, I used `sed` to replace the first occurrence of `%Bin` with `%PDF`.

```bash
sed '1s/%Bin/%PDF/' ch13.bin > ch13.pdf
```

## Flag
**CTF{hidden_in_plainsight_djbh67jn}**
