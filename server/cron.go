package server

import (
	"os"

	"github.com/robfig/cron/v3"
)

// SetupCronTasks run two functions every hour
func (c *Server) SetupCronTasks() {
	cron := cron.New()
	var cadence = "0 * * * *"
	if os.Getenv("ENV") == "production" {
		cadence = "1 * * * *"
	}
	if _, err := cron.AddFunc(cadence, func() {
		if err := c.rotateIssuers(); err != nil {
			panic(err)
		}
	}); err != nil {
		panic(err)
	}
	if _, err := cron.AddFunc(cadence, func() {
		if err := c.rotateIssuerV3(); err != nil {
			panic(err)
		}
	}); err != nil {
		panic(err)
	}
	cron.Start()
}
