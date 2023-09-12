package metrics

import (
	"fmt"
	"log"
	"net/http"
	"net/http/pprof"
	"runtime"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	GoVersion string = runtime.Version()
)

var (
	CounterConnections = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "attempted_conns",
		Help: "Successful connections made to blindsigmgmt",
	})
	CounterConnErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "conn_errors",
		Help: "Number of failed connection attempts",
	})
	CounterRedeemTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "total_redeem",
		Help: "Total number of redemption requests",
	})
	CounterRedeemSuccess = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "total_redeem_success",
		Help: "Total number of successful token redemptions",
	})
	CounterRedeemError = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "total_redeem_error",
		Help: "Total number of errors with redemption requests",
	})
	CounterRedeemErrorFormat = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "total_redeem_error_format",
		Help: "Total number of errors due to malformed redemption requests",
	})
	CounterRedeemErrorVerify = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "total_redeem_error_verify",
		Help: "Total number of failed verification attempts of redeemed tokens",
	})
	CounterIssueTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "total_issue",
		Help: "Total number of issue requests",
	})
	CounterIssueSuccess = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "total_issue_success",
		Help: "Total number of successful token issue requests",
	})
	CounterIssueError = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "total_issue_error",
		Help: "Total number of errors with issue requests",
	})
	CounterIssueErrorFormat = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "total_issue_error_format",
		Help: "Total number of errors due to malformed issue requests",
	})
	CounterJsonError = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "total_json_error",
		Help: "Total number of incorrect JSON failures",
	})
	CounterDoubleSpend = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "total_double_spend",
		Help: "Total number of double spend detections",
	})
	CounterUnknownRequestType = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "total_unk_req_type",
		Help: "Total number of verification errors due to failure reading req type",
	})
	BuildInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "build_info",
			Help: "A metric with a constant '1' value labeled by version, and goversion from which btd was built.",
		},
		[]string{"version", "goversion"},
	)
)

func RegisterAndListen(listenAddr string, errLog *log.Logger) {
	collector := []prometheus.Collector{
		CounterConnections, CounterConnErrors, CounterRedeemTotal,
		CounterRedeemSuccess, CounterRedeemError, CounterRedeemErrorFormat,
		CounterRedeemErrorVerify, CounterIssueTotal, CounterIssueSuccess,
		CounterIssueError, CounterIssueErrorFormat, CounterJsonError,
		CounterDoubleSpend, CounterUnknownRequestType, BuildInfo,
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(collector...)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))

	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	mux.HandleFunc("/debug/version", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "GoVersion: %s", GoVersion)
	})

	server := http.Server{
		Handler:  mux,
		Addr:     listenAddr,
		ErrorLog: errLog,
	}

	errLog.Printf("metrics listening on %s", listenAddr)
	err := server.ListenAndServe()
	errLog.Printf("failed to serve metrics: %v", err)
}
