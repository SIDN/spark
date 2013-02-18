package main

import (
	"bufio"
	"flag"
	"github.com/miekg/dns"
	"github.com/miekg/unbound"
	"log"
	"os"
	"strings"
	"time"
)

var domainfile = flag.String("domain", "", "file with domain names")
var resolver = flag.String("resolver", "127.0.0.1", "resolver to use")
var routines = flag.Int("goroutines", 250, "number of goroutines")

func main() {
	flag.Parse()
	if *domainfile == "" {
		log.Fatalf("domainfile is empty\n")
	}
	f, e := os.Open(*domainfile)
	if e != nil {
		log.Fatalf("Failed to open %s: %s\n", *domainfile, e.Error())
	}
	defer f.Close()
	u := unbound.New()
	defer u.Destroy()
	u.AddTaFile("Kroot.key")

	if *resolver != "" {
		if e := u.SetFwd(*resolver); e != nil {
			log.Fatalf("Failed to set resolver %s\n", e.Error())
		}
	} else {
		u.ResolvConf("/etc/resolv.conf")
	}

	chout := make(chan [2]string)
	chin := make(chan string)

	r := bufio.NewReader(f)
	for i := 0; i < *routines; i++ {
		go dnssecCrawl(u, chin, chout)
	}
	line, _, e := r.ReadLine()
	go func() {
		for e == nil {
			dom := strings.TrimSpace(string(line))
			chin <- dom
			line, _, e = r.ReadLine()
		}
		if e != nil {
			time.Sleep(10 * 1e9) // 10 s wait
			close(chin)
			close(chout)
		}
	}()

	for ret := range chout {
		log.Printf("%s:%s", ret[0], ret[1])
	}
}

func dnssecCrawl(u *unbound.Unbound, chin chan string, chout chan [2]string) {
	for {
		select {
		case d := <-chin:
			res, err := u.Resolve(d, dns.TypeSOA, dns.ClassINET)
			if err != nil {
				chout <- [2]string{d, err.Error()}
				continue
			}
			if res.HaveData {
				if res.Secure {
					chout <- [2]string{d, "secure"}
					continue
				}
				if res.Bogus {
					chout <- [2]string{d, "bogus" + ":" + res.WhyBogus}
					continue
				}
				chout <- [2]string{d, "insecure"}
				continue
			}
			chout <- [2]string{d, "nodata"}
		}
	}
}
