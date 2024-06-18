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
		203, 44, 144, 190, 181, 16, 222, 35, 137, 147,
		96, 136, 37, 100, 199, 84, 29, 116, 0, 38, 178,
		224, 189, 9, 224, 32, 45, 235, 130, 177, 255, 40,
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
