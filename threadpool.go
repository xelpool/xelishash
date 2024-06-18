package xelishash

import "unsafe"

type ThreadPool struct {
	scratch chan *ScratchPadV2
}

func NewThreadPool(threads int) *ThreadPool {
	tp := &ThreadPool{
		scratch: make(chan *ScratchPadV2, threads),
	}

	for i := 0; i < threads; i++ {
		tp.scratch <- &ScratchPadV2{}
	}

	return tp
}

// Hash accepts algorithm name as string (example: xel/0, xel/1)
func (t *ThreadPool) Hash(algo string, input []byte) [32]byte {
	if algo == "xel/1" { // XelisHash v2
		return t.XelisHashV2(input)
	}
	return t.XelisHash(input)
}

func (t *ThreadPool) XelisHash(input []byte) [32]byte {
	scratch := <-t.scratch

	defer func() {
		t.scratch <- scratch
	}()

	return XelisHash(input, (*ScratchPad)(unsafe.Pointer(scratch)))
}

func (t *ThreadPool) XelisHashV2(input []byte) [32]byte {
	scratch := <-t.scratch

	defer func() {
		t.scratch <- scratch
	}()

	return XelisHashV2(input, scratch)
}
