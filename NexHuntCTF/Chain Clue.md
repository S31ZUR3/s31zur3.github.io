Forensics
#### 1. Reconnaissance

Since we were given a transaction hash and the network name, the first step was to inspect the transaction using a Block Explorer. For the Sepolia testnet, the standard explorer is **Sepolia Etherscan**.

#### 2. Analysis

I navigated to the transaction page: `https://sepolia.etherscan.io/tx/0x1c1e14180c2e5dceefc260208199e23a8c61524dd54bd2e378cee00e14555c14`

On the transaction details page, I examined the standard fields (From, To, Value). The value was `0 ETH`, indicating this transaction likely carried data rather than value.

I looked at the **"Input Data"** field (also known as `calldata`). By default, Etherscan displays this in Hexadecimal format.

**Hex Data:**

Plaintext

```
0x6e657875737b54723463335f5468335f5472346e7334637431306e7d
```

#### 3. Decoding

The Hex string looked like standard ASCII encoding. I converted the view on Etherscan to **UTF-8** (or used a local Hex-to-Text converter).

- `0x6e` -> `n`
    
- `0x65` -> `e`
    
- `0x78` -> `x`
    
- ...and so on.
    

#### 4. Flag Capture

Converting the hex data revealed the plaintext flag directly.

**Flag:**

Plaintext

```
nexus{Tr4c3_Th3_Tr4ns4ct10n}
```
