// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

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
	var testProbe bool
	var testProbeCount int

	flag.StringVar(&configPath, "config", "", "file path of the client configuration TOML file")
	flag.StringVar(&logLevel, "log_level", "DEBUG", "logging level could be set to: DEBUG, INFO, WARNING, ERROR, CRITICAL")
	flag.StringVar(&listenAddr, "listen", "", "local socket to listen HTTP on")
	flag.BoolVar(&testProbe, "probe", false, "send test probes instead of handling requests")
	flag.IntVar(&testProbeCount, "probe_count", 1, "number of test probes to send")
	flag.Parse()

	if listenAddr == "" && !testProbe {
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

	if testProbe {
		server.SendTestProbes(10*time.Second, testProbeCount)
	} else {
		http.HandleFunc("/", server.Handler)
		err := http.ListenAndServe(listenAddr, nil)
		if err != nil {
			// Check if the error is related to the port being in use
			if strings.Contains(err.Error(), "bind: address already in use") {
				mylog.Errorf("Cannot start server: Listen port %s is already in use. Please check if another instance of walletshield is running or use another port.", listenAddr)
			} else {
				mylog.Errorf("Failed to start HTTP server: %s", err)
			}
		}
	}
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
		s.log.Errorf("Failed to send message: %s", err)
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

	responsePayloadStr := string(response.Payload)
	if strings.Contains(strings.ToLower(responsePayloadStr), "error") {
		s.log.Errorf("Error in REPLY")
	} else {
		s.log.Infof("Successful REPLY: %s", responsePayloadStr)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(response.Payload)))
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, string(response.Payload))
}

func (s *Server) SendTestProbes(d time.Duration, testProbeCount int) {
	req, err := http.NewRequest("GET", "http://nowhere/_/probe", nil)
	buf := new(bytes.Buffer)
	req.Write(buf)
	request := new(http_proxy.Request)
	request.Payload = buf.Bytes()
	blob, err := cbor.Marshal(request)
	if err != nil {
		panic(err)
	}

	var packetsTransmitted, packetsReceived int
	var rttMin, rttMax, rttTotal float64
	rttMin = math.MaxFloat64

	for {
		packetsTransmitted++
		t := time.Now()
		_, err := s.session.BlockingSendUnreliableMessage(s.target.Name, s.target.Provider, blob)
		elapsed := time.Since(t).Seconds()
		if err != nil {
			s.log.Errorf("Probe failed after %.2fs: %s", elapsed, err)
		} else {
			packetsReceived++
			rttTotal += elapsed
			if elapsed < rttMin {
				rttMin = elapsed
			}
			if elapsed > rttMax {
				rttMax = elapsed
			}
			s.log.Infof("Probe response took %.2fs", elapsed)
		}

		packetLoss := float64(packetsTransmitted-packetsReceived) / float64(packetsTransmitted) * 100
		rttAvg := rttTotal / float64(packetsReceived)
		s.log.Infof("Probe packet transmitted/received/loss = %d/%d/%.1f%%", packetsTransmitted, packetsReceived, packetLoss)
		s.log.Infof("Probe rtt min/avg/max = %.2f/%.2f/%.2f s", rttMin, rttAvg, rttMax)

		// probe indefinitely if testProbeCount is 0
		if testProbeCount != 0 && packetsTransmitted >= testProbeCount {
			os.Exit(0)
		}

		time.Sleep(d)
	}
}
