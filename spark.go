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

var domainfile = flag.String("domain", "", "file containing domain and registrar names")

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
	u.ResolvConf("/etc/resolv.conf")
	u.AddTaFile("Kroot.key")

	ch := make(chan [2]string)

	r := bufio.NewReader(f)
	line, _, e := r.ReadLine()
	go func() {
		for e == nil {
			dom := strings.TrimSpace(string(line))
			go dnssecCrawl(u, dom, ch)
			line, _, e = r.ReadLine()
		}
		if e != nil {
			time.Sleep(10 * 1e9) // 10 s wait
			close(ch)
		}
	}()

	for ret := range ch {
		log.Printf(ret[0], ":", ret[1])
	}
}

func dnssecCrawl(u *unbound.Unbound, d string, ch chan [2]string) {
	res, err := u.Resolve(d, dns.TypeSOA, dns.ClassINET)
	if err != nil {
		ch <- [2]string{d, err.Error()}
		return
	}

	if res.HaveData {
		if res.Secure {
			ch <- [2]string{d, "secure"}
			return
		}
		if res.Bogus {
			ch <- [2]string{d, "bogus"}
			return
		}
		ch <- [2]string{d, "insecure"}
		return
	}
	ch <- [2]string{d, "nodata"}
	return
}
