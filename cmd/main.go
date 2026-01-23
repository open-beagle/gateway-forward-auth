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

	// Log configuration summary
	log.WithFields(map[string]interface{}{
		"provider":    config.DefaultProvider,
		"auth_host":   config.AuthHost,
		"cookie_name": config.CookieName,
		"log_level":   config.LogLevel,
	}).Info("Configuration loaded")

	// Start session cleanup goroutine
	tfa.StartSessionCleanup(time.Minute * 5)

	// Build server
	server := tfa.NewServer()

	// Attach router to default server
	http.HandleFunc("/", server.RootHandler)

	// Start
	log.WithField("config", config).Debug("Starting with config")
	log.Info("Listening on :4181")
	log.Info(http.ListenAndServe(fmt.Sprintf(":%d", config.Port), nil))
}
