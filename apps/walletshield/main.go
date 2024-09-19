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

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client2"
	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/client2/thin"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"

	"github.com/0KnowledgeNetwork/opt/server_plugins/cbor_plugins/http_proxy"
)

var (
	timeout          = time.Second * 200
	ProxyHTTPService = "http_proxy"
)

func sendRequest(thin *thin.ThinClient, nodeId *[32]byte, recipientQueueID []byte, payload []byte) ([]byte, error) {
	surbID := &[sConstants.SURBIDLength]byte{}
	_, err := rand.Reader.Read(surbID[:])
	if err != nil {
		panic(err)
	}
	timeoutCtx, _ := context.WithTimeout(context.TODO(), timeout)
	return thin.BlockingSendMessage(timeoutCtx, payload, nodeId, recipientQueueID)
}

type Server struct {
	log    *log.Logger
	daemon *client2.Daemon
	thin   *thin.ThinClient
}

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
		Prefix: "walletshield:",
		Level:  level,
	})

	// start client2 daemon
	cfg, err := config.LoadFile(configPath)
	if err != nil {
		panic(err)
	}

	d, err := client2.NewDaemon(cfg)
	if err != nil {
		panic(err)
	}
	err = d.Start()
	if err != nil {
		panic(err)
	}

	time.Sleep(time.Second * 3) // XXX ugly hack but works: FIXME

	thin := thin.NewThinClient(cfg)
	err = thin.Dial()
	if err != nil {
		panic(err)
	}

	/*

		desc, err := thin.GetService(ProxyHTTPService)
		if err != nil {
			panic(err)
		}
	*/
	// http server
	server := &Server{
		log:    mylog,
		thin:   thin,
		daemon: d,
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

func (s *Server) Handler(w http.ResponseWriter, req *http.Request) {
	s.log.Infof("Received HTTP request for %s", req.URL)

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

	s.log.Debugf("RAW HTTP REQUEST:\n%s", string(buf.Bytes()))

	blob, err := cbor.Marshal(request)
	if err != nil {
		panic(err)
	}

	target, err := s.thin.GetService(ProxyHTTPService)
	if err != nil {
		panic(err)
	}
	nodeId := hash.Sum256(target.MixDescriptor.IdentityKey)
	rawReply, err := sendRequest(s.thin, &nodeId, target.RecipientQueueID, blob)
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

	if response.Error != "" {
		s.log.Errorf("Response Error: %s", response.Error)
	} else {
		s.log.Infof("Response: %s", response.Payload)
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

		// Select a target service node and compute the DestinationIdHash

		surbID := &[sConstants.SURBIDLength]byte{}
		_, err := rand.Reader.Read(surbID[:])
		if err != nil {
			panic(err)
		}
		target, err := s.thin.GetService(ProxyHTTPService)
		if err != nil {
			panic(err)
		}
		nodeId := hash.Sum256(target.MixDescriptor.IdentityKey)
		_, err = sendRequest(s.thin, &nodeId, target.RecipientQueueID, blob)
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
