// Command vulnserver runs the intentionally vulnerable demo application used
// to exercise sqli locally. Bind it to loopback only.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/akshaytheflash/antisqli/internal/vulnapp"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8099", "listen address")
	flag.Parse()

	fmt.Fprintf(os.Stderr, "vulnerable demo app listening on http://%s\n", *addr)
	fmt.Fprintln(os.Stderr, "WARNING: intentionally insecure. Loopback use only.")
	if err := http.ListenAndServe(*addr, vulnapp.Handler()); err != nil {
		log.Fatal(err)
	}
}
