package metrics

// https://github.com/dlmiddlecote/sqlstats
// Copyright (c) 2019 Daniel Middlecote
// Modified here to maintain many stats collectors for many database connections

import (
	"database/sql"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	namespace = "go_dbstats"
	subsystem = "connections"
)

// StatsGetter is an interface that gets sql.DBStats.
// It's implemented by e.g. *sql.DB or *sqlx.DB.
type StatsGetter interface {
	Stats() sql.DBStats
}

// SG - StatsGetter Attributes
type SG struct {
	DBName string
	Stats  StatsGetter
}

// StatsCollector implements the prometheus.Collector interface.
type StatsCollector struct {
	mu  *sync.Mutex
	sgs []SG

	// descriptions of exported metrics
	maxOpenDesc           *prometheus.Desc
	openDesc              *prometheus.Desc
	inUseDesc             *prometheus.Desc
	idleDesc              *prometheus.Desc
	waitedForDesc         *prometheus.Desc
	blockedSecondsDesc    *prometheus.Desc
	closedMaxIdleDesc     *prometheus.Desc
	closedMaxLifetimeDesc *prometheus.Desc
}

// AddStatsGetter - Add a new db name and stats getter pair which will be reported on
func (sc *StatsCollector) AddStatsGetter(dbName string, sg StatsGetter) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.sgs = append(sc.sgs, SG{
		DBName: dbName,
		Stats:  sg,
	})
}

// NewStatsCollector creates a new StatsCollector.
func NewStatsCollector(dbName string, sg StatsGetter) *StatsCollector {
	return &StatsCollector{
		mu: &sync.Mutex{},
		sgs: []SG{
			{
				DBName: dbName,
				Stats:  sg,
			},
		},
		maxOpenDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "max_open"),
			"Maximum number of open connections to the database.",
			[]string{"db_name"},
			nil,
		),
		openDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "open"),
			"The number of established connections both in use and idle.",
			[]string{"db_name"},
			nil,
		),
		inUseDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "in_use"),
			"The number of connections currently in use.",
			[]string{"db_name"},
			nil,
		),
		idleDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "idle"),
			"The number of idle connections.",
			[]string{"db_name"},
			nil,
		),
		waitedForDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "waited_for"),
			"The total number of connections waited for.",
			[]string{"db_name"},
			nil,
		),
		blockedSecondsDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "blocked_seconds"),
			"The total time blocked waiting for a new connection.",
			[]string{"db_name"},
			nil,
		),
		closedMaxIdleDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "closed_max_idle"),
			"The total number of connections closed due to SetMaxIdleConns.",
			[]string{"db_name"},
			nil,
		),
		closedMaxLifetimeDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "closed_max_lifetime"),
			"The total number of connections closed due to SetConnMaxLifetime.",
			[]string{"db_name"},
			nil,
		),
	}
}

// Describe implements the prometheus.Collector interface.
func (sc StatsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- sc.maxOpenDesc
	ch <- sc.openDesc
	ch <- sc.inUseDesc
	ch <- sc.idleDesc
	ch <- sc.waitedForDesc
	ch <- sc.blockedSecondsDesc
	ch <- sc.closedMaxIdleDesc
	ch <- sc.closedMaxLifetimeDesc
}

// Collect implements the prometheus.Collector interface.
func (sc StatsCollector) Collect(ch chan<- prometheus.Metric) {
	for _, sg := range sc.sgs {
		stats := sg.Stats.Stats()
		dbName := sg.DBName

		ch <- prometheus.MustNewConstMetric(
			sc.maxOpenDesc,
			prometheus.GaugeValue,
			float64(stats.MaxOpenConnections),
			dbName,
		)
		ch <- prometheus.MustNewConstMetric(
			sc.openDesc,
			prometheus.GaugeValue,
			float64(stats.OpenConnections),
			dbName,
		)
		ch <- prometheus.MustNewConstMetric(
			sc.inUseDesc,
			prometheus.GaugeValue,
			float64(stats.InUse),
			dbName,
		)
		ch <- prometheus.MustNewConstMetric(
			sc.idleDesc,
			prometheus.GaugeValue,
			float64(stats.Idle),
			dbName,
		)
		ch <- prometheus.MustNewConstMetric(
			sc.waitedForDesc,
			prometheus.CounterValue,
			float64(stats.WaitCount),
			dbName,
		)
		ch <- prometheus.MustNewConstMetric(
			sc.blockedSecondsDesc,
			prometheus.CounterValue,
			stats.WaitDuration.Seconds(),
			dbName,
		)
		ch <- prometheus.MustNewConstMetric(
			sc.closedMaxIdleDesc,
			prometheus.CounterValue,
			float64(stats.MaxIdleClosed),
			dbName,
		)
		ch <- prometheus.MustNewConstMetric(
			sc.closedMaxLifetimeDesc,
			prometheus.CounterValue,
			float64(stats.MaxLifetimeClosed),
			dbName,
		)
	}
}
