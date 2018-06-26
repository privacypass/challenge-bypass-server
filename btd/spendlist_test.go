package btd

import (
	"runtime"
	"strconv"
	"sync"
	"testing"

	boom "github.com/tylertreat/BoomFilters"
)

func NewTestList() *DoubleSpendList {
	return &DoubleSpendList{
		filter: boom.NewStableBloomFilter(10000000, 8, 0.000001),
	}
}

func BenchmarkFilterAdd(b *testing.B) {
	f := NewTestList()
	for i := 0; i < b.N; i++ {
		f.AddToken([]byte(strconv.Itoa(i)))
	}
}

func BenchmarkFilterLookup(b *testing.B) {
	f := NewTestList()

	f.AddToken([]byte("abc"))

	for i := 0; i < b.N; i++ {
		rand := (1103515245*i + 12345) & 0xFFFFFFFF
		f.CheckToken([]byte(strconv.Itoa(rand)))
	}
}

func TestDoubleSpendList(t *testing.T) {
	f := NewTestList()

	if f.CheckToken([]byte("abc")) {
		t.Error("abc shouldn't be in list")
	}

	f.AddToken([]byte("abc"))

	if !f.CheckToken([]byte("abc")) {
		t.Error("abc should be in list")
	}

	if f.CheckToken([]byte("123")) {
		t.Error("123 should not be in the list")
	}

}

func TestFilterEviction(t *testing.T) {
	if testing.Short() {
		t.Skip("this one takes forever")
	}

	f := NewTestList()

	f.AddToken([]byte("abc"))

	// add 100k new entries in parallel to test locks
	runtime.GOMAXPROCS(runtime.NumCPU())
	var wg sync.WaitGroup
	wg.Add(4)
	for i := 0; i < 4; i++ {
		go func(index int) {
			defer wg.Done()
			for j := index * 25000; j < (index+1)*25000; j++ {
				rand := (1103515245*j + 12345) & 0xFFFFFFFF
				f.AddToken([]byte(strconv.Itoa(rand)))
			}
		}(i)
	}
	wg.Wait()

	if !f.CheckToken([]byte("abc")) {
		t.Error("abc should not have been evicted")
	}
}
