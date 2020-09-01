package metrics

import (
	"database/sql"
	"testing"
)

type MockStatsGetter struct {
	MockStats func() sql.DBStats
}

func (msg *MockStatsGetter) Stats() sql.DBStats {
	if msg.MockStats == nil {
		return sql.DBStats{}
	}
	return msg.MockStats()
}

func TestStatsCollectorInit(t *testing.T) {
	sc := NewStatsCollector("testdb", &MockStatsGetter{})
	sc.AddStatsGetter("testdb1", &MockStatsGetter{})

	// make sure both stats getters are there
	if len(sc.sgs) != 2 {
		t.Error("Failed to add the new stats getter")
	}

	var (
		foundTest1 bool
		foundTest  bool
	)

	for _, sg := range sc.sgs {
		if sg.DBName == "testdb" {
			foundTest = true
		}
		if sg.DBName == "testdb1" {
			foundTest1 = true
		}
	}
	if !foundTest1 || !foundTest {
		t.Error("failed to find the two required db names from stats getter")
	}
}
