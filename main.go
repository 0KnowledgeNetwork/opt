package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"

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

		// NOTE(david): do we care which headers are set? Probably not.
		//req.Header["Connection"] = []string{"close"}
		req.Header = http.Header{}

		myurl, err := url.Parse(req.RequestURI)
		if err != nil {
			mylog.Errorf("url.Parse(req.RequestURI) failed: %s", err)
			return
		}
		req.URL = myurl
		req.RequestURI = ""

		buf := new(bytes.Buffer)
		req.Write(buf)

		request := new(http_proxy.Request)
		request.Payload = buf.Bytes()

		mylog.Infof("RAW HTTP REQUEST: %s", string(buf.Bytes()))

		blob, err := cbor.Marshal(request)
		if err != nil {
			panic(err)
		}

		rawReply, err := session.BlockingSendReliableMessage(desc.Name, desc.Provider, blob)
		if err != nil {
			panic(err)
		}

		// use the streaming decoder and simply return the first cbor object
		// and then discard the decoder and buffer
		response := new(http_proxy.Response)
		dec := cbor.NewDecoder(bytes.NewReader(rawReply))
		err = dec.Decode(response)
		if err != nil {
			panic(err)
		}

		mylog.Infof("REPLY: '%s'", rawReply)

		if response.ChunksTotal == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(rawReply)))
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, string(response.Payload))
		} else {
			// XXX TODO(david):
			// do clever things with SURBs
		}
	}
	http.HandleFunc("/", handler)
	http.ListenAndServe(listenAddr, nil)
}
