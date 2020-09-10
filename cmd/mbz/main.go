package main

import (
	"flag"

	"github.com/moznion/mudy-bluez"
)

func main() {
	var tls bool
	flag.BoolVar(&tls, "tls", false, "use TLS to send the request")

	flag.Parse()

	args := flag.Args()

	mudybluez.Run(args[0], tls)
}
