package cron

import (
	"github.com/robfig/cron"
)

type Spec int

const (
	HOURLY Spec = iota
	DAILY
	WEEKLY
	MONTHLY
	YEARLY
)

func (s Spec) String() string {
	if s == HOURLY {
		return "@hourly"
	}
	if s == DAILY {
		return "@daily"
	}
	if s == WEEKLY {
		return "@weekly"
	}
	if s == MONTHLY {
		return "@monthly"
	}
	if s == YEARLY {
		return "@yearly"
	}
	return "unknown"
}

type Cron struct {
	c *cron.Cron
}

func New() *Cron {
	return &Cron{
		c: cron.New(),
	}
}

func (c *Cron) Start() {
	c.c.Start()
}

func (c *Cron) Add(spec Spec, fn func()) error {
	return c.c.AddFunc(spec.String(), fn)
}

func (c *Cron) Stop() {
	c.c.Start()
}
