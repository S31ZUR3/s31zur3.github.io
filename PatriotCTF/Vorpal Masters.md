rev
## 🔍 Challenge Summary

We are given a binary that prompts the user for a license key using the format:

`xxxx-xxxx-xxxxxxxxxx`

Our objective is to reverse engineer the binary, determine the validation logic, and generate a valid license key.

---

## 🧩 Program Analysis

The key input is parsed using:

`scanf("%4s-%d-%10s", &local_11, &local_20, local_1c);`

The key is split into:

|Segment|Content Type|Target Variable|
|---|---|---|
|First|4 characters|local_11 … local_e|
|Second|Integer|local_20|
|Third|10 characters|local_1c|

---

## 1️⃣ First Segment Validation

The binary checks:

`if(local_11 != 'C' || local_f != 'C' || local_e != 'I' || local_10 != 'A')     womp_womp();`

Due to structure layout, the correct order of the first 4 characters is:

`CACI`

✔ Required first segment ⇒ `CACI`

---

## 2️⃣ Second Segment Validation

Must be in range:

`-5000 < local_20 < 10000`

and satisfy:

`(local_20 + 22) % 1738 == (((local_20 * 2) % 2000) * 6) + 9`

We brute-forced all valid values in the range and found **exactly one solution**:

`local_20 = 2025`

✔ Required middle number ⇒ `2025`

---

## 3️⃣ Third Segment Validation

The string must match exactly:

`strcmp(local_1c, "PatriotCTF") == 0`

✔ Required last segment ⇒ `PatriotCTF`

---

## 🎯 Final Valid License Key

`CACI-2025-PatriotCTF`

Entering this into the program yields:

`License key registered, you may play the game now!`

---

## 🏁 Conclusion

By reversing the validation checks and solving a modular arithmetic constraint, we successfully obtained the only valid key:

> **CACI{CACI-2025-PatriotCTF}**

Challenge solved 🚀
[[PatriotCTF-2025]]