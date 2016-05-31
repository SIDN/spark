//
//
// Tool to resolve a (large) file of domain names in an efficient fashion
// Meant to test domainnames in various ways, in particular to see if they validate
//
// SIDN Labs 2013
//
//

package main

import (
	"bufio"
	"flag"
	"fmt"
	"strconv"
	"github.com/miekg/dns"
	"github.com/miekg/unbound"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"crypto/rand"
	"reflect"
)

var domainfile = flag.String("names", "", "file with domain names")
var resolver = flag.String("resolver", "", "IP-addr for caching proxy or 'none' or entirely empty for /etc/resolv.conf")
var rrtype = flag.String("rrtype", "A", "Pick any RR type (most common are implemented, otherwise try RFC3597-style")
var routines = flag.Int("goroutines", 50, "number of goroutines")
var print_rrs = flag.Bool("print_rrs", false, "print the resource records (if any)")
// sometimes we want to trigger and force 'denial of existence'
var randomize = flag.Bool("randomize", false, "Add a random qname-label (for deeper inspection, but it may trigger RRL)")
var insecure = flag.Bool("insecure", false, "Do not check DNSSEC")

var rcode string
var strX int

var qtype = uint16(1)

// Random string generator
func randString(n int) string {
    const alphanum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    var bytes = make([]byte, n)
    rand.Read(bytes)
    for i, b := range bytes {
        bytes[i] = alphanum[b % byte(len(alphanum))]
    }
    return string(bytes)
}

func Sprint(rr dns.RR) (s string) {
	v := reflect.ValueOf(rr).Elem()
	// Cheat a little, the header is contained in i = 0, so we start with 1
	for i := 1; i < v.NumField(); i++ {
		// copy some (all?) code from msg.go
		switch fv := v.Field(i); fv.Kind() {
		case reflect.String:
			s += fv.String()
		case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			s += strconv.FormatUint(fv.Uint(), 10)
		case reflect.Slice:
			switch v.Type().Field(i).Tag {
			case `dns:"txt"`:
				for j := 0; j < fv.Len(); j++ {
					if j > 0 {
						s += " "
					}
					s += strconv.QuoteToASCII(fv.Index(j).String())
				}
            case `dns:"a"`:
                s += strconv.FormatUint(fv.Index(12).Uint(), 10)
                s += "."
                s += strconv.FormatUint(fv.Index(13).Uint(), 10)
                s += "."
                s += strconv.FormatUint(fv.Index(14).Uint(), 10)
                s += "."
                s += strconv.FormatUint(fv.Index(15).Uint(), 10)
            default:
                s += "unimplemented type: "
                s += string(v.Type().Field(i).Tag)
            }
		default:
			s += "Error unpacking RR"
		}
		s += " "
	}
	return s
}


func main() {

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s -names filename [options]\nCurrent settings:\n", os.Args[0])
		flag.PrintDefaults()
	}


	flag.Parse()

	// get RR type
	if k, ok := dns.StringToType[strings.ToUpper(*rrtype)]; ok {
		qtype = k
	}
	// RFC3597-style
	if strings.HasPrefix(*rrtype, "TYPE") {
		i, e := strconv.Atoi(string([]byte(*rrtype)[4:]))
			if e == nil {
				if i > 0 && i <= 65535 {
					qtype = uint16(i)
				}
			}
	}
		

	var f io.ReadCloser
	var e error
	if *domainfile == "" {
		f = os.Stdin
	} else {
		f, e = os.Open(*domainfile)
		if e != nil {
			log.Fatalf("Failed to open %s: %s\n", *domainfile, e.Error())
		}
	}
	defer f.Close()
	u := unbound.New()
	defer u.Destroy()
    if !*insecure {
        u.AddTa(`;; ANSWER SECTION:
.                       168307 IN DNSKEY 257 3 8 (
                                AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQ
                                bSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh
                                /RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37NZWA
                                JQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXp
                                oY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3
                                LQpzW5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGO
                                Yl7OyQdXfZ57relSQageu+ipAdTTJ25AsRTAoub8ONGc
                                LmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0=
                                ) ; key id = 19036`)
    }

	if *resolver != "" && *resolver != "none" {
		if e := u.SetFwd(*resolver); e != nil {
			log.Fatalf("Failed to set resolver %s\n", e.Error())
		} else {
			// DEBUG fmt.Println("Using " + *resolver + "...\n")
		}
	} else {
		if *resolver == "" {
			// DEBUG
			// fmt.Println("Using /etc/resolv.conf...\n")
			u.ResolvConf("/etc/resolv.conf")
		} else {
			// DEBUG fmt.Println("Not using any caching proxy...\n")
		}
	}

	chout := make(chan [2]string, *routines*2)
	chin := make(chan string, *routines*2)
	stop := make([]chan bool, *routines)

	r := bufio.NewReader(f)
	wg := new(sync.WaitGroup)
	wg.Add(*routines)
	for i := 0; i < *routines; i++ {
		stop[i] = make(chan bool)
		go lookup(u, chin, chout, wg, stop[i])
	}
	line, _, e := r.ReadLine()
	go func() {
		for e == nil {
			dom := strings.TrimSpace(string(line))
			chin <- dom
			line, _, e = r.ReadLine()
		}
		if e != nil {
			for i := 0; i < *routines; i++ {
				stop[i] <- true
			}
			wg.Wait()
			close(chin)
			close(chout)
		}
	}()

	for ret := range chout {
		fmt.Println(ret[0],":",ret[1])
	}
}

func lookup(u *unbound.Unbound, chin chan string, chout chan [2]string, wg *sync.WaitGroup, stop chan bool) {

	for {
		select {
		case <-stop:
			wg.Done()
			return
		case d := <-chin:
			if *randomize {
				strX = len(d)
				if strX > 249 { // empty string will become '.'
					chout <- [2]string{d, "is too long for an additional randomization label, refraining"}
					continue
				} else {
					d = randString(5) + "." + d
				}
			}
			res, err := u.Resolve(d, qtype, dns.ClassINET)
			// TODO: what is the best type to ask for?
			if err != nil {
				chout <- [2]string{d, err.Error()}
				continue
			}

			if res.Rcode==0 {
				rcode="(0 - noerror)"
			} else {
				if res.Rcode==2 {
					rcode="(2 - servfail)"
				} else {
					if res.Rcode==3 {
						rcode="(3 - nxdomain)"
					} else {
						rcode=fmt.Sprintf("(rcode: %d)", res.Rcode)
					}
				}
			}
 
			if res.HaveData || res.NxDomain {
				if (*print_rrs && len(res.Rr) > 0) {
					for _,r := range(res.Rr) {
						chout <- [2]string{d, Sprint(r)}
					}
				}
                if !*insecure {
                    if res.Secure {
                        chout <- [2]string{d, "secure"}
                        continue
                    }
                    if res.Bogus {
                        chout <- [2]string{d, "bogus" + ":" + res.WhyBogus}
                        continue
                    }
                    chout <- [2]string{d, "insecure"}
                } else if res.NxDomain {
                    chout <- [2]string{res.Qname, "nodata " + rcode}
                }
				continue
			}
			// return the qname instead of 'd' (because we always want to terminate with a dot)
			chout <- [2]string{res.Qname, "nodata " + rcode}
		}
	}
}
