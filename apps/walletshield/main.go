package main

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/katzenpost/hpqc/hash"
	"net/http"
	"os"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/client2"
	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/core/log"
)

func main() {
	// Command-line flags
	var configPath, logFile, logLevel string
	var disableLogging bool

	flag.StringVar(&configPath, "config", "client.toml", "Path to client configuration file")
	flag.StringVar(&logLevel, "log_level", "DEBUG", "Set the logging level")
	flag.StringVar(&logFile, "log_file", "", "Log file path")
	flag.BoolVar(&disableLogging, "disable_logging", false, "Disable logging")
	flag.Parse()

	// Initialize logging
	logBackend, err := log.New(logFile, logLevel, disableLogging)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logging: %v\n", err)
		os.Exit(1)
	}
	logger := logBackend.GetLogger("client2")

	// Load configuration
	cfg, err := config.LoadFile(configPath)
	if err != nil {
		logger.Errorf("Configuration loading failed: %v", err)
		os.Exit(1)
	}

	// Initialize the Katzenpost client
	client, err := client2.New(cfg, logBackend)
	if err != nil {
		logger.Errorf("Failed to create Katzenpost client: %v", err)
		os.Exit(1)
	}

	// Start the client
	err = client.Start()
	if err != nil {
		logger.Errorf("Failed to start client: %v", err)
		os.Exit(1)
	}

	// Start HTTP server to handle incoming requests
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handleHTTPRequest(client, w, r, logger)
	})
	logger.Infof("Starting HTTP server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		logger.Errorf("Failed to start HTTP server: %v", err)
	}
}

func handleHTTPRequest(client *client2.Client, w http.ResponseWriter, r *http.Request, logger *logging.Logger) {
	logger.Infof("Received HTTP request for %s", r.URL.Path)

	// Read the request payload
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		logger.Errorf("Failed to read request body: %v", err)
		return
	}
	requestData := buf.Bytes()

	// Get the current document from the client's PKI
	_, doc := client.CurrentDocument()
	if doc == nil {
		http.Error(w, "Failed to retrieve PKI document", http.StatusInternalServerError)
		logger.Errorf("Failed to retrieve PKI document")
		return
	}

	// Select a target service node and compute the DestinationIdHash
	var destinationIdHash [32]byte
	if len(doc.ServiceNodes) > 0 {
		node := doc.ServiceNodes[0] // Choose the first service node for simplicity
		destinationIdHash = hash.Sum256(node.IdentityKey)
	} else {
		http.Error(w, "No service nodes available", http.StatusInternalServerError)
		logger.Errorf("No service nodes available in PKI document")
		return
	}

	// Set the RecipientQueueID based on the service you are targeting
	recipientQueueID := []byte("+walletshield")

	// Prepare the client2 Request object for the mix network
	mixRequest := &client2.Request{
		DestinationIdHash: &destinationIdHash,
		RecipientQueueID:  recipientQueueID,
		Payload:           requestData,
		WithSURB:          true,
		IsARQSendOp:       true,
	}

	// Send the request via the mix network
	surbKey, rtt, err := client.SendCiphertext(mixRequest)
	if err != nil {
		http.Error(w, "Failed to send packet", http.StatusInternalServerError)
		logger.Errorf("Failed to send packet: %v", err)
		return
	}
	logger.Infof("Packet sent successfully, estimated RTT: %s", rtt)

	// Optionally, wait for a reply if necessary
	replyPayload, err := waitForReply(client, mixRequest.ID) // Placeholder function
	if err != nil {
		http.Error(w, "Failed to receive reply", http.StatusInternalServerError)
		logger.Errorf("Failed to receive reply: %v", err)
		return
	}

	// Write the reply back to the HTTP client
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(replyPayload)))
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(replyPayload)
	if err != nil {
		logger.Errorf("Failed to write response: %v", err)
	}
}

func waitForReply(client *client2.Client, messageID *[client2.MessageIDLength]byte) ([]byte, error) {
	// Implement the logic to wait and retrieve the reply here
	return nil, nil // Placeholder return
}
