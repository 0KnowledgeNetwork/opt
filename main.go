package main

import (
	"bytes"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/charmbracelet/log"

	"github.com/katzenpost/katzenpost/client"
)

func main() {
	var logLevel string
	var listenAddr string
	var configPath string

	flag.StringVar(&configPath, "config", "", "file path of the client configuration TOML file")
	flag.StringVar(&logLevel, "log_level", "DEBUG", "logging level could be set to: DEBUG, INFO, WARNING, ERROR, CRITICAL")
	flag.StringVar(&listenAddr, "listen", "", "destination URL for reverse proxying to")
	flag.Parse()

	if listenAddr == "" {
		panic("listen flag must be set")
	}
	if configPath == "" {
		panic("config flag must be set")
	}

	// logging
	level, err := log.ParseLevel(logLevel)
	if err != nil {
		panic(err)
	}
	mylog := log.NewWithOptions(os.Stdout, log.Options{
		Prefix: "daemon",
		Level:  level,
	})

	// mixnet client
	cfg, err := config.LoadFile(configPath)
	if err != nil {
		panic(err)
	}
	client, err := New(cfg)
	if err != nil {
		panic(err)
	}
	session, err := client.NewTOFUSession(context.Background())
	if err != nil {
		panic(err)
	}
	ProxyHTTPService := "http_proxy"
	desc, err := session.GetService(ProxyHTTPService)
	if err != nil {
		panic(err)
	}

	// http server
	handler := func(w http.ResponseWriter, req *http.Request) {
		mylog.Info("received http request")

		buf := new(bytes.Buffer)
		req.Write(buf)

		msgID, err := session.SendReliableMessage(desc.Name, desc.Provider, buf.Bytes())

		fmt.Fprintf(w, "hello\n")
	}
	http.HandleFunc("/", handler)
	http.ListenAndServe(listenAddr, nil)
}
