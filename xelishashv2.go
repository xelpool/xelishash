package xelishash

import (
	"encoding/binary"
	"math/bits"
	"unsafe"

	"github.com/chocolatkey/chacha8"
	"github.com/zeebo/blake3"
	"lukechampine.com/uint128"
)

// These are tweakable parameters
// Memory size is the size of the scratch pad in u64s
// In bytes, this is equal to ~ 440KB
const MEMORY_SIZE_V2 = 429 * 128

// ScratchPadV2 iterations in stage 3
const SCRATCHPAD_ITERS_V2 = 3

// Buffer size for stage 3 (inner loop iterations)
const BUFFER_SIZE_V2 = MEMORY_SIZE_V2 / 2

// Stage 1 config
const CHUNK_SIZE_V2 = 32
const NONCE_SIZE_V2 = 12
const OUTPUT_SIZE_V2 = MEMORY_SIZE_V2 * 8

// Stage 3 AES key
const KEY = "xelishash-pow-v2"

// ScratchPadV2 used to store intermediate values
// It has a fixed size of `MEMORY_SIZE_V2` u64s
// It can be easily reused for multiple hashing operations safely
type ScratchPadV2 [MEMORY_SIZE_V2]uint64

// Stage 1 of the hashing algorithm
// This stage is responsible for generating the scratch pad
// The scratch pad is generated using Chacha8 with a custom nonce
// that is updated after each iteration
func stage_1_v2(input []byte, scratch_pad *[MEMORY_SIZE_V2 * 8]byte) {
	output_offset := 0
	nonce := [NONCE_SIZE_V2]byte{}

	// Generate the nonce from the input
	input_hash := blake3.Sum256(input)
	copy(nonce[:], input_hash[:NONCE_SIZE_V2])

	num_chunks := (len(input) + CHUNK_SIZE_V2 - 1) / CHUNK_SIZE_V2

	for chunk_index := 0; chunk_index < num_chunks; chunk_index++ {
		chunk := input[chunk_index*CHUNK_SIZE_V2:]

		// Concatenate the input hash with the chunk
		tmp := [HASH_SIZE * 2]byte{}
		copy(tmp[0:HASH_SIZE], input_hash[:])
		copy(tmp[HASH_SIZE:], chunk)

		// Hash it to not trust the input
		input_hash = blake3.Sum256(tmp[:])

		cipher, err := chacha8.New(input_hash[:], nonce[:])
		if err != nil {
			panic(err)
		}

		// Calculate the remaining size and how much to generate this iteration
		current_output_size := OUTPUT_SIZE_V2 - output_offset
		// Remaining chunks
		chunks_left := num_chunks - chunk_index
		chunk_output_size := current_output_size / chunks_left
		if current_output_size > chunk_output_size {
			current_output_size = chunk_output_size
		}

		// Apply the keystream to the output
		offset := chunk_index * current_output_size
		part := scratch_pad[offset : offset+current_output_size]
		cipher.KeyStream(part)

		output_offset += current_output_size

		// Update the nonce with the last NONCE_SIZE_V2 bytes of temp_output
		nonce_start := current_output_size - NONCE_SIZE_V2
		if nonce_start < 0 {
			nonce_start = 0
		}

		// Copy the new nonce
		copy(nonce[:], part[nonce_start:])
	}
}

// Stage 3 of the hashing algorithm
// This stage is responsible for hashing the scratch pad
// Its goal is to have lot of random memory accesses
// and some branching to make it hard to optimize on GPUs
// it shouldn't be possible to parallelize this stage
func stage_3(scratch_pad *ScratchPadV2) {
	key := [16]byte([]byte(KEY))
	block := [16]byte{}

	// Create two new slices for each half
	mem_buffer_a := scratch_pad[:BUFFER_SIZE_V2]
	mem_buffer_b := scratch_pad[BUFFER_SIZE_V2:]

	addr_a := mem_buffer_b[BUFFER_SIZE_V2-1]
	addr_b := mem_buffer_a[BUFFER_SIZE_V2-1] >> 32
	var r int = 0

	for i := 0; i < SCRATCHPAD_ITERS_V2; i++ {
		mem_a := mem_buffer_a[int(addr_a%BUFFER_SIZE_V2)]
		mem_b := mem_buffer_b[int(addr_b%BUFFER_SIZE_V2)]

		copy(block[:8], (toBytesLE(&mem_b))[:])
		copy(block[8:], (toBytesLE(&mem_a))[:])

		aesRound2(&block, &key)

		hash1 := binary.LittleEndian.Uint64(block[:8])

		hash2 := mem_a ^ mem_b
		result := ^(hash1 ^ hash2)

		for j := 0; j < BUFFER_SIZE_V2; j++ {
			a := mem_buffer_a[int(result%BUFFER_SIZE_V2)]
			b := mem_buffer_b[int(^bits.RotateLeft64(result, -r)%BUFFER_SIZE_V2)]
			var c uint64
			if r < BUFFER_SIZE_V2 {
				c = mem_buffer_a[r]
			} else {
				c = mem_buffer_b[r-BUFFER_SIZE_V2]
			}
			if r < MEMORY_SIZE_V2-1 {
				r++
			} else {
				r = 0
			}

			var v uint64

			switch bits.RotateLeft64(result, int(c)) & 0xf {
			case 0:
				v = result ^ bits.RotateLeft64(c, int(i*j)) ^ b
			case 1:
				v = result ^ bits.RotateLeft64(c, -int(i*j)) ^ a
			case 2:
				v = result ^ a ^ b ^ c
			case 3:
				v = result ^ (a+b)*c
			case 4:
				v = result ^ (b-c)*a
			case 5:
				v = result ^ (c - a + b)
			case 6:
				v = result ^ (a - b + c)
			case 7:
				v = result ^ (b*c + a)
			case 8:
				v = result ^ (c*a + b)
			case 9:
				v = result ^ a*b*c
			case 10:
				t1 := uint128.Uint128{Hi: a, Lo: b}
				v = result ^ (t1.Mod64(c | 1))
			case 11:
				t1 := uint128.Uint128{Hi: b, Lo: c}
				t2 := uint128.Uint128{Hi: bits.RotateLeft64(result, r), Lo: a | 2}
				v = result ^ t1.Mod(t2).Lo
			case 12:
				t1 := uint128.Uint128{Hi: c, Lo: a}
				v = result ^ (t1.Div64(b | 4).Lo)
			case 13:
				t1 := uint128.Uint128{Hi: bits.RotateLeft64(result, r), Lo: b}
				t2 := uint128.Uint128{Hi: a, Lo: c | 8}

				if t1.Cmp(t2) > 0 {
					v = result ^ t1.Div(t2).Lo
				} else {
					v = result ^ (a ^ b)
				}
			case 14:
				t1 := uint128.Uint128{Hi: b, Lo: a}
				t2 := uint128.Uint128{Lo: c}
				v = result ^ t1.MulWrap(t2).Hi
			case 15:
				t1 := uint128.Uint128{Hi: a, Lo: c}
				t2 := uint128.Uint128{
					Hi: bits.RotateLeft64(result, -r),
					Lo: b,
				}
				v = result ^ t1.MulWrap(t2).Hi
			}

			result = bits.RotateLeft64(v, 1)

			t := mem_buffer_a[BUFFER_SIZE_V2-j-1] ^ result
			mem_buffer_a[BUFFER_SIZE_V2-j-1] = t
			mem_buffer_b[j] ^= bits.RotateLeft64(t, -int(result))
		}
		addr_a = result
		addr_b = isqrt(result)
	}
}

func isqrt(n uint64) uint64 {
	if n < 2 {
		return n
	}

	x := n
	y := (x + 1) >> 1

	for y < x {
		x = y
		y = (x + (n / x)) >> 1
	}

	return x
}

// This function is used to hash the input using the generated scratch pad
// NOTE: The ScratchPadV2 is completely overwritten in stage 1  and can be reused without any issues
func XelisHashV2(input []byte, scratch_pad *ScratchPadV2) [32]byte {
	// stage 1
	scratchpad_bytes := (*[MEMORY_SIZE_V2 * 8]byte)(unsafe.Pointer(scratch_pad))
	stage_1_v2(input, scratchpad_bytes)

	// stage 2 got removed as it got completely optimized on GPUs

	// stage 3
	stage_3(scratch_pad)

	// stage 4
	return blake3.Sum256(scratchpad_bytes[:])
}
