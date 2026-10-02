---
title: Day 1
date: 2026-10-02
category: Reverse Engineering
tags: series, rev
difficulty: Easy
summary: An easy rev chall from HTB
---

# Simple Encryptor

This challenge is a simple rev chall that takes in an flag and performs some operations on it and outputs an encrypted flag.

Below is the decompilation of the encryption part:

```C
for (i = 0; i < max; i = i + 1) {
    temp = rand();
    *(b + i) = *(b + i) ^ temp;
    a = rand();
    a = a & 7;
    *(b + i) = *(b + i) << a | *(b + i) >> 8 - a;
}
```
What this does is it **XOR's** the array with the random number generated from *rand()*. Then another variable is also initialized to get the value from *rand()*. Then this variable goes tthrough a bitwise `&` operation with 7. After this the array goes through right shift operation and left shift operation.

Reversing this encryption is simple.
```C
for (long i = 0; i < max; i++) {
        int temp = rand();
        int a = rand();
        a = a & 7;
        *(b + i) = (*(b + i) >> a) | (*(b + i) << (8 - a));
        *(b + i) = *(b + i) ^ temp;
}
```
We just write the same for loop and the only changes we are making here are just this one line `*(b + i) = *(b + i) << a | *(b + i) >> 8 - a;` to `*(b + i) = (*(b + i) >> a) | (*(b + i) << (8 - a));`.

I feel like I still got it in me :)))).