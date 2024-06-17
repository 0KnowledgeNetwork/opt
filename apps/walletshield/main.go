// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

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
	"github.com/katzenpost/katzenpost/client/utils"

	"github.com/0KnowledgeNetwork/opt/server_plugins/cbor_plugins/http_proxy"
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
	server := &Server{
		log:     mylog,
		session: session,
		target:  desc,
	}
	http.HandleFunc("/", server.Handler)
	http.ListenAndServe(listenAddr, nil)
}

type Server struct {
	log     *log.Logger
	session *client.Session
	target  *utils.ServiceDescriptor
}

func (s *Server) Handler(w http.ResponseWriter, req *http.Request) {
	s.log.Info("received http request")

	myurl, err := url.Parse(req.RequestURI)
	if err != nil {
		s.log.Errorf("url.Parse(req.RequestURI) failed: %s", err)
		return
	}
	req.URL = myurl
	req.RequestURI = ""

	buf := new(bytes.Buffer)
	req.Write(buf)

	request := new(http_proxy.Request)
	request.Payload = buf.Bytes()

	s.log.Infof("RAW HTTP REQUEST: %s", string(buf.Bytes()))

	blob, err := cbor.Marshal(request)
	if err != nil {
		panic(err)
	}

	rawReply, err := s.session.BlockingSendUnreliableMessage(s.target.Name, s.target.Provider, blob)
	if err != nil {
		s.log.Errorf("Failed to send reliable message: %s", err)
		http.Error(w, "custom 404", http.StatusNotFound)
		return
	}

	// use the streaming decoder and simply return the first cbor object
	// and then discard the decoder and buffer
	response := new(http_proxy.Response)
	dec := cbor.NewDecoder(bytes.NewReader(rawReply))
	err = dec.Decode(response)
	if err != nil {
		s.log.Errorf("Failed to decode response: %s", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	s.log.Infof("REPLY: '%s'", rawReply)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(response.Payload)))
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, string(response.Payload))
}
