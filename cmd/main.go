package main

import (
	"fmt"
	"net/http"
	"time"

	tfa "github.com/thomseddon/traefik-forward-auth/internal"
)

// Main
func main() {
	// Print banner
	tfa.PrintBanner()

	// Parse options
	config := tfa.NewGlobalConfig()

	// Setup logger
	log := tfa.NewDefaultLogger()

	// Perform config validation
	config.Validate()

	// Start session cleanup goroutine
	tfa.StartSessionCleanup(time.Minute * 5)

	// Build server
	server := tfa.NewServer()

	// Attach router to default server
	http.HandleFunc("/", server.RootHandler)

	// Start
	log.WithField("config", config).Debug("Starting with config")
	log.Infof("Listening on :%d", config.Port)
	log.Info(http.ListenAndServe(fmt.Sprintf(":%d", config.Port), nil))
}
