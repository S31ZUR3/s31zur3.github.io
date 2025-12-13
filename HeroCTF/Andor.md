crypto
## 🔍 Analysis

The flag is split into two halves:

|Half|Operation|Output|
|---|---|---|
|First half|`flag & random`|printed as `a`|
|Second half|`flag|random`|

Each round uses a **new random key**, but the flag is static.

---

## 🧠 Vulnerability

### 🔹 First half (AND leak)

For each bit:

`flag_bit AND random_bit`

|Flag bit|Result|
|---|---|
|0|always 0|
|1|sometimes 1|

👉 If we OR together results over many rounds, we recover all bits that ever become 1 → this reconstructs the first half.

---

### 🔹 Second half (OR leak)

For each bit:

`flag_bit OR random_bit`

|Flag bit|Result|
|---|---|
|1|always 1|
|0|sometimes 0|

👉 If we AND together results over many rounds, only constant 1 bits survive → this reconstructs the second half.

---

## ⚔️ Attack Strategy

Repeat the connection many times.

- OR all AND outputs → reveals first half
    
- AND all OR outputs → reveals second half
    

This cancels randomness and leaks the full flag.

---

## 🧑‍💻 Exploit Script

### Python solution:
```
import socket

HOST = "crypto.heroctf.fr"
PORT = 9000
ROUNDS = 300

and_acc = None
or_acc = None

for i in range(ROUNDS):
    s = socket.create_connection((HOST, PORT))
    data = s.recv(4096).decode().splitlines()
    s.close()

    a = bytes.fromhex(data[0].split("=")[1].strip())
    o = bytes.fromhex(data[1].split("=")[1].strip())

    if and_acc is None:
        and_acc = list(a)
        or_acc = list(o)
    else:
        and_acc = [x | y for x, y in zip(and_acc, a)]
        or_acc = [x & y for x, y in zip(or_acc, o)]

    if i % 25 == 0:
        print(f"[+] Iteration {i}")

flag = bytes(and_acc + or_acc)
print("FLAG:", flag.decode())
```
---

## ✅ Result

After ~200–300 rounds:

`Hero{y0u_4nd_5l33p_0r_y0u_4nd_c0ff33_3qu4l5_fl4g_4nd_p01n75}`

[[HeroCTF 2025]]

