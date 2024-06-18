package xelishash

import (
	"crypto/rand"
	"testing"
	"time"
)

func TestReusedScratchpad(t *testing.T) {
	scratchpad := ScratchPadV2{}
	input := make([]byte, 112)
	rand.Read(input)

	expected_hash := XelisHashV2(input, &scratchpad)

	hash := XelisHashV2(input, &scratchpad)

	if hash != expected_hash {
		t.Fatalf("incorrect hash: %x, expected: %x", hash, expected_hash)
	}
}

func TestZeroHash(t *testing.T) {
	scratchpad := ScratchPadV2{}
	input := make([]byte, 112)

	hash := XelisHashV2(input, &scratchpad)
	expectedHash := [32]byte{
		203, 44, 144, 190, 181, 16, 222, 35, 137, 147,
		96, 136, 37, 100, 199, 84, 29, 116, 0, 38, 178,
		224, 189, 9, 224, 32, 45, 235, 130, 177, 255, 40,
	}

	if hash != expectedHash {
		t.Fatalf("incorrect hash: %x, expected: %x", hash, expectedHash)
	}
}

func TestVerifyOutput(t *testing.T) {
	input := []byte{
		172, 236, 108, 212, 181, 31, 109, 45, 44, 242, 54, 225, 143, 133,
		89, 44, 179, 108, 39, 191, 32, 116, 229, 33, 63, 130, 33, 120, 185, 89,
		146, 141, 10, 79, 183, 107, 238, 122, 92, 222, 25, 134, 90, 107, 116,
		110, 236, 53, 255, 5, 214, 126, 24, 216, 97, 199, 148, 239, 253, 102,
		199, 184, 232, 253, 158, 145, 86, 187, 112, 81, 78, 70, 80, 110, 33,
		37, 159, 233, 198, 1, 178, 108, 210, 100, 109, 155, 106, 124, 124, 83,
		89, 50, 197, 115, 231, 32, 74, 2, 92, 47, 25, 220, 135, 249, 122,
		172, 220, 137, 143, 234, 68, 188,
	}

	scratchpad := ScratchPadV2{}

	hash := XelisHashV2(input, &scratchpad)

	expectedHash := [32]byte{
		1, 93, 81, 131, 95, 75, 134, 32, 61, 179, 217, 243,
		212, 132, 191, 89, 98, 98, 214, 61, 217, 127, 124,
		152, 220, 30, 245, 117, 230, 226, 255, 139,
	}

	if hash != expectedHash {
		t.Fatalf("incorrect hash: %x, expected: %x", hash, expectedHash)
	}
}

func BenchmarkHashV2(b *testing.B) {
	var scratch_pad ScratchPadV2

	var input = make([]byte, 112)

	b.Log(b.N)
	t := time.Now()

	for i := 0; i < b.N; i++ {
		XelisHashV2(input, &scratch_pad)
	}

	deltaT := float64(time.Since(t).Nanoseconds()) / nanosecond

	b.Log("H/s:", float64(b.N)/deltaT)

}
