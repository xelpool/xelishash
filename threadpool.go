package xelishash

type ThreadPool struct {
	scratch chan *ScratchPad
}

func NewThreadPool(threads int) *ThreadPool {
	tp := &ThreadPool{
		scratch: make(chan *ScratchPad, threads),
	}

	for i := 0; i < threads; i++ {
		tp.scratch <- &ScratchPad{}
	}

	return tp
}

func (t *ThreadPool) XelisHash(input []byte) ([32]byte, error) {
	scratch := <-t.scratch

	defer func() {
		t.scratch <- scratch
	}()

	return XelisHash(input, scratch)
}
