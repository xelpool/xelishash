package xelishash

import (
	"testing"
)

func TestThreadPool(t *testing.T) {
	tp := NewThreadPool(4)
	errchan := make(chan error)

	var input = make([]byte, 200)

	for i2 := 0; i2 < 40; i2++ {
		i := i2
		go func() {
			hashdata, err := tp.XelisHash(input)
			if err != nil {
				errchan <- err
			}
			t.Logf("thread %d data %x", i, hashdata)
			errchan <- nil
		}()
	}
	for i := 0; i < 40; i++ {
		err := <-errchan
		if err != nil {
			t.Fatal(err)
		}
	}

}
