package server

import (
	"github.com/robfig/cron/v3"
)

// SetupCronTasks run two functions every hour
func (c *Server) SetupCronTasks() {
	cron := cron.New()
	if _, err := cron.AddFunc("* * * * *", func() {
		if err := c.rotateIssuers(); err != nil {
			panic(err)
		}
	}); err != nil {
		panic(err)
	}
	cron.Start()
}
