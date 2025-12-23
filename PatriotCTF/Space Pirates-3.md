rev

This writeup explains how to solve the "Space Pirates 3" CTF challenge.

The challenge is a Go program that takes a 30-character string as input and encrypts it through a series of six operations. The goal is to find the input string that produces a specific target hash.

The six operations are:

1.  `applyUltimateQuantumCipher`: XORs the input with a 7-byte key.
2.  `applyStellarRotationV2`: Rotates each byte to the left by a specific amount based on its position.
3.  `applySpatialTransposition`: Swaps every two adjacent bytes.
4.  `applyGravitationalShiftV3`: Subtracts a constant value from each byte.
5.  `applyTemporalInversionV2`: Reverses the order of the bytes in 6-byte chunks.
6.  `applyCoordinateCalibrationV3`: XORs each byte with a value derived from its position in the string.

To solve the challenge, we need to reverse these operations in the reverse order they were applied. This means starting with the target hash and applying the inverse of each operation, from step 6 back to step 1.

The inverse operations are:

1.  `reverseCoordinateCalibrationV3`: XOR each byte with the same position-derived value. This is the same as the original operation, as XOR is its own inverse.
2.  `reverseTemporalInversionV2`: Reverse the bytes in 6-byte chunks again. This is also the same as the original operation.
3.  `reverseGravitationalShiftV3`: Add the constant value to each byte.
4.  `reverseSpatialTransposition`: Swap every two adjacent bytes again. This is the same as the original operation.
5.  `reverseStellarRotationV2`: Rotate each byte to the right by the same amount.
6.  `reverseUltimateQuantumCipher`: XOR the input with the same 7-byte key.

By applying these inverse operations to the target hash, we can recover the original input string, which is the flag.

The following Go program implements this logic:

```go
package main

import "fmt"

// The target encrypted vault combination (what we want the transformed input to become)
var target = [30]byte{
	0x60, 0x6D, 0x5D, 0x97, 0x2C, 0x04, 0xAF, 0x7C, 0xE2, 0x9E, 0x77, 0x85, 0xD1, 0x0F, 0x1D, 0x17, 0xD4, 0x30, 0xB7, 0x48, 0xDC, 0x48, 0x36, 0xC1, 0xCA, 0x28, 0xE1, 0x37, 0x58, 0x0F,
}

// The Pirate King's ULTIMATE XOR key (7 bytes - prime number for better mixing!)
var xorKey = [7]byte{0xC7, 0x2E, 0x89, 0x51, 0xB4, 0x6D, 0x1F}

// NEW: Rotation pattern (8 bytes, includes rotation by 0 which is identity)
var rotationPattern = [8]uint{7, 5, 3, 1, 6, 4, 2, 0}

// The Pirate King's subtraction constant (much larger than before!)
const magicSub byte = 0x93

// Chunk size for reversal (changed from 5 to 6!)
const chunkSize = 6

// rotateRight rotates a byte right by n positions (inverse of rotateLeft)
func rotateRight(b byte, n uint) byte {
	n = n % 8 // Ensure n is in range [0,7]
	return (b >> n) | (b << (8 - n))
}

// Inverse of OPERATION 6: applyCoordinateCalibrationV3
func reverseCoordinateCalibrationV3(buffer []byte) {
	for i := range buffer {
		positionValue := ((i * i) + i) % 256
		buffer[i] ^= byte(positionValue)
	}
}

// Inverse of OPERATION 5: applyTemporalInversionV2
func reverseTemporalInversionV2(buffer []byte) {
	for chunkStart := 0; chunkStart < len(buffer); chunkStart += chunkSize {
		chunkEnd := chunkStart + chunkSize
		if chunkEnd > len(buffer) {
			chunkEnd = len(buffer)
		}
		for i, j := chunkStart, chunkEnd-1; i < j; i, j = i+1, j-1 {
			buffer[i], buffer[j] = buffer[j], buffer[i]
		}
	}
}

// Inverse of OPERATION 4: applyGravitationalShiftV3
func reverseGravitationalShiftV3(buffer []byte) {
	for i := range buffer {
		buffer[i] += magicSub
	}
}

// Inverse of OPERATION 3: applySpatialTransposition
func reverseSpatialTransposition(buffer []byte) {
	for i := 0; i < len(buffer)-1; i += 2 {
		buffer[i], buffer[i+1] = buffer[i+1], buffer[i]
	}
}

// Inverse of OPERATION 2: applyStellarRotationV2
func reverseStellarRotationV2(buffer []byte) {
	for i := range buffer {
		rotation := rotationPattern[i%len(rotationPattern)]
		buffer[i] = rotateRight(buffer[i], rotation)
	}
}

// Inverse of OPERATION 1: applyUltimateQuantumCipher
func reverseUltimateQuantumCipher(buffer []byte) {
	for i := range buffer {
		buffer[i] ^= xorKey[i%len(xorKey)]
	}
}

func main() {
	buffer := target[:]

	// Apply inverse operations in reverse order
	reverseCoordinateCalibrationV3(buffer)
	reverseTemporalInversionV2(buffer)
	reverseGravitationalShiftV3(buffer)
	reverseSpatialTransposition(buffer)
	reverseStellarRotationV2(buffer)
	reverseUltimateQuantumCipher(buffer)

	fmt.Printf("Found flag: %s\n", string(buffer))
}
```

Running this program will print the flag:

```
PCTF{M4ST3R_0F_TH3_S3V3N_S34S}
```

[[PatriotCTF-2025]]