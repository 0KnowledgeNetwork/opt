package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/katzenpost/katzenpost/client2"
	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/core/log"
)

func main() {
	// Command-line flags
	var configPath, logLevel, logFile string
	var disableLogging bool

	flag.StringVar(&configPath, "config", "client.toml", "Path to client configuration file")
	flag.StringVar(&logLevel, "log_level", "DEBUG", "Set the logging level")
	flag.StringVar(&logFile, "log_file", "", "Log file path")
	flag.BoolVar(&disableLogging, "disable_logging", false, "Disable logging")
	flag.Parse()

	// Initialize logging
	logBackend, err := setupLogging(logFile, logLevel, disableLogging)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to set up logging: %v\n", err)
		os.Exit(1)
	}

	// Load configuration
	cfg, err := config.LoadFile(configPath)
	if err != nil {
		panic(err)
	}

	// Initialize the Katzenpost client
	client, err := client2.New(cfg, logBackend)
	if err != nil {
		panic(err)

	}
	// Ensure client is cleanly shut down
	defer client.Shutdown()

	// HTTP server setup
	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintln(w, "Hello, World!")
	})

	// Start HTTP server
	if err = http.ListenAndServe(":8080", nil); err != nil {
		panic(err)
	}
}

func setupLogging(filePath string, level string, disable bool) (*log.Backend, error) {
	// Initialize the logging backend
	backend, err := log.New(filePath, level, disable)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize logging backend: %v", err)
	}
	return backend, nil
}
