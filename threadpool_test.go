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

	for i2 := 0; i2 < 8; i2++ {
		go func() {
			result := tp.XelisHashV2(inputV2)
			t.Logf("xelishash v2 result: %x", result)
			if result != expectedHashV2 {
				panic(fmt.Errorf("invalid result %x, expected %x", result, expectedHashV2))
			}
			endchan <- true
		}()
	}
	for i := 0; i < 8; i++ {
		<-endchan
	}
}
