package btd

import (
	"sync"

	boom "github.com/tylertreat/BoomFilters"
)

type DoubleSpendList struct {
	lock   sync.RWMutex
	filter *boom.StableBloomFilter
}

// Amongst a profusion of bloom filter variants, this one at least uses a
// strictly bounded amount of memory. Ideally you would use something better.
// Napkin estimates: 10M * 8-bit buckets ~ 80MB with 1/1000000 asymptotic false
// positive rate.
func NewDoubleSpendList() *DoubleSpendList {
	return &DoubleSpendList{
		filter: boom.NewStableBloomFilter(10000000, 8, 0.000001),
	}
}

func (d *DoubleSpendList) CheckToken(token []byte) bool {
	d.lock.RLock()
	defer d.lock.RUnlock()
	return d.filter.Test(token)
}

func (d *DoubleSpendList) AddToken(token []byte) {
	d.lock.Lock()
	defer d.lock.Unlock()
	d.filter.Add(token)
}

func (d *DoubleSpendList) Reset() {
	d.lock.Lock()
	defer d.lock.Unlock()
	d.filter.Reset()
}
