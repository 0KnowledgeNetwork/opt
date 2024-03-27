package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/charmbracelet/log"
	"github.com/fxamacker/cbor/v2"

	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/server_plugins/cbor_plugins/http_proxy"
)

func main() {
	var logLevel string
	var listenAddr string
	var configPath string

	flag.StringVar(&configPath, "config", "", "file path of the client configuration TOML file")
	flag.StringVar(&logLevel, "log_level", "DEBUG", "logging level could be set to: DEBUG, INFO, WARNING, ERROR, CRITICAL")
	flag.StringVar(&listenAddr, "listen", "", "local socket to listen HTTP on")
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
	c, err := client.New(cfg)
	if err != nil {
		panic(err)
	}
	session, err := c.NewTOFUSession(context.Background())
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

		// we care about some headers, but not most
		req.Header = http.Header{
			// "Connection":     []string{"close"},
			"Content-Type":   []string{req.Header.Get("Content-Type")},
			"Content-Length": []string{req.Header.Get("Content-Length")},
		}

		myurl, err := url.Parse(req.RequestURI)
		if err != nil {
			mylog.Errorf("url.Parse(req.RequestURI) failed: %s", err)
			return
		}
		req.URL = myurl
		req.RequestURI = ""

		buf := new(bytes.Buffer)
		req.Write(buf)

		response := new(http_proxy.Request)
		response.Payload = buf.Bytes()

		mylog.Infof("RAW HTTP REQUEST: %s", string(buf.Bytes()))

		blob, err := cbor.Marshal(response)
		if err != nil {
			panic(err)
		}

		rawReply, err := session.BlockingSendReliableMessage(desc.Name, desc.Provider, blob)
		if err != nil {
			fmt.Fprint(w, "custom 404")
		}

		reply := strings.Trim(string(rawReply), "\x00")

		mylog.Infof("REPLY: '%s'", reply)

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(reply)))

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, string(reply))
	}
	http.HandleFunc("/", handler)
	http.ListenAndServe(listenAddr, nil)
}
