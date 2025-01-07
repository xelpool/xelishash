package xelishash

import (
	"fmt"
	"testing"
)

func TestThreadPool(t *testing.T) {
	tp := NewThreadPool(4)
	endchan := make(chan bool)

	var input = make([]byte, 200)

	for i2 := 0; i2 < 40; i2++ {
		go func() {
			tp.XelisHash(input)
			endchan <- true
		}()
	}
	for i := 0; i < 40; i++ {
		<-endchan
	}

	inputV2 := input[:112]

	expectedHashV2 := [32]byte{
		126, 219, 112, 240, 116, 133, 115, 144, 39, 40, 164,
		105, 30, 158, 45, 126, 64, 67, 238, 52, 200, 35,
		161, 19, 144, 211, 214, 225, 95, 190, 146, 27,
	}

	inputV2_2 := []byte{
		172, 236, 108, 212, 181, 31, 109, 45, 44, 242, 54, 225, 143, 133,
		89, 44, 179, 108, 39, 191, 32, 116, 229, 33, 63, 130, 33, 120, 185, 89,
		146, 141, 10, 79, 183, 107, 238, 122, 92, 222, 25, 134, 90, 107, 116,
		110, 236, 53, 255, 5, 214, 126, 24, 216, 97, 199, 148, 239, 253, 102,
		199, 184, 232, 253, 158, 145, 86, 187, 112, 81, 78, 70, 80, 110, 33,
		37, 159, 233, 198, 1, 178, 108, 210, 100, 109, 155, 106, 124, 124, 83,
		89, 50, 197, 115, 231, 32, 74, 2, 92, 47, 25, 220, 135, 249, 122,
		172, 220, 137, 143, 234, 68, 188,
	}

	expectedHashV2_2 := [32]byte{
		199, 114, 154, 28, 4, 164, 196, 178, 117, 17, 148,
		203, 125, 228, 51, 145, 162, 222, 106, 202, 205,
		55, 244, 178, 94, 29, 248, 242, 98, 221, 158, 179,
	}

	for i2 := 0; i2 < 50; i2++ {
		if i2%2 == 0 {
			go func() {
				result := tp.XelisHashV2(inputV2)
				t.Logf("xelishash v2 result 1: %x", result)
				if result != expectedHashV2 {
					panic(fmt.Errorf("invalid result %x, expected %x", result, expectedHashV2))
				}
				endchan <- true
			}()
		} else {
			go func() {
				result := tp.XelisHashV2(inputV2_2)
				t.Logf("xelishash v2 result 2: %x", result)
				if result != expectedHashV2_2 {
					panic(fmt.Errorf("invalid result %x, expected %x", result, expectedHashV2))
				}
				endchan <- true
			}()
		}
	}
	for i := 0; i < 50; i++ {
		<-endchan
	}
}
