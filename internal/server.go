package tfa

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/thomseddon/traefik-forward-auth/internal/provider"
	muxhttp "github.com/traefik/traefik/v2/pkg/muxer/http"
)

// AuthFlowTracker tracks ongoing authentication flows
type AuthFlowTracker struct {
	inProgress   bool
	startTime    time.Time
	timeout      time.Duration
	requestCount int32 // 原子计数器，用于排序请求
	mutex        sync.RWMutex
}

// NewAuthFlowTracker creates a new auth flow tracker
func NewAuthFlowTracker() *AuthFlowTracker {
	return &AuthFlowTracker{
		timeout: 30 * time.Minute,
	}
}

// Start starts an authentication flow and returns the request number (1-based)
func (t *AuthFlowTracker) Start() int32 {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if !t.inProgress {
		// First request, start the flow
		t.inProgress = true
		t.startTime = time.Now()
		t.requestCount = 1
		return 1
	}

	// Subsequent request
	t.requestCount++
	return t.requestCount
}

// IsInProgress checks if an authentication flow is in progress
func (t *AuthFlowTracker) IsInProgress() bool {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	if !t.inProgress {
		return false
	}

	// Check if timeout
	if time.Since(t.startTime) > t.timeout {
		return false
	}

	return true
}

// Clear clears the authentication flow
func (t *AuthFlowTracker) Clear() {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.inProgress = false
	t.requestCount = 0
}

// IsTimeout checks if the flow has timed out
func (t *AuthFlowTracker) IsTimeout() bool {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	return t.inProgress && time.Since(t.startTime) > t.timeout
}

// SSEConnectionPool manages SSE connections
type SSEConnectionPool struct {
	connections map[string]chan string
	mutex       sync.RWMutex
}

// NewSSEConnectionPool creates a new SSE connection pool
func NewSSEConnectionPool() *SSEConnectionPool {
	return &SSEConnectionPool{
		connections: make(map[string]chan string),
	}
}

// AddConnection adds a new SSE connection
func (p *SSEConnectionPool) AddConnection(id string, ch chan string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.connections[id] = ch
}

// RemoveConnection removes an SSE connection
func (p *SSEConnectionPool) RemoveConnection(id string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if ch, ok := p.connections[id]; ok {
		close(ch)
		delete(p.connections, id)
	}
}

// Broadcast broadcasts an event to all connections
func (p *SSEConnectionPool) Broadcast(event string) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	for _, ch := range p.connections {
		select {
		case ch <- event:
		default:
			// Channel full or closed, skip
		}
	}
}

// Count returns the number of active connections
func (p *SSEConnectionPool) Count() int {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return len(p.connections)
}

// Server contains muxer and handler methods
type Server struct {
	muxer        *muxhttp.Muxer
	authTracker  *AuthFlowTracker
	ssePool      *SSEConnectionPool
	waitingCount int
	waitingMutex sync.Mutex
}

// NewServer creates a new server object and builds muxer
func NewServer() *Server {
	s := &Server{
		authTracker: NewAuthFlowTracker(),
		ssePool:     NewSSEConnectionPool(),
	}
	s.buildRoutes()
	return s
}

func (s *Server) buildRoutes() {
	var err error
	s.muxer, err = muxhttp.NewMuxer()
	if err != nil {
		log.Fatal(err)
	}

	// Let's build a muxer
	for name, rule := range config.Rules {
		matchRule := rule.formattedRule()
		if rule.Action == "allow" {
			_ = s.muxer.AddRoute(matchRule, 1, s.AllowHandler(name))
		} else {
			_ = s.muxer.AddRoute(matchRule, 1, s.AuthHandler(rule.Provider, name))
		}
	}

	// Add callback handler
	s.muxer.Handle(config.Path, s.AuthCallbackHandler())

	// Add logout handler
	s.muxer.Handle(config.Path+"/logout", s.LogoutHandler())

	// Add debug handler (for debugging user info)
	s.muxer.Handle(config.Path+"/debug", s.DebugHandler())

	// Add SSE wait handler (for multi-tab auth)
	s.muxer.Handle(config.Path+"/wait", s.SSEWaitHandler())

	// Add a default handler
	if config.DefaultAction == "allow" {
		s.muxer.NewRoute().Handler(s.AllowHandler("default"))
	} else {
		s.muxer.NewRoute().Handler(s.AuthHandler(config.DefaultProvider, "default"))
	}
}

// RootHandler Overwrites the request method, host and URL with those from the
// forwarded request so it's correctly routed by mux
func (s *Server) RootHandler(w http.ResponseWriter, r *http.Request) {
	// Modify request
	r.Method = r.Header.Get("X-Forwarded-Method")
	r.Host = r.Header.Get("X-Forwarded-Host")

	// Read URI from header if we're acting as forward auth middleware
	if _, ok := r.Header["X-Forwarded-Uri"]; ok {
		r.URL, _ = url.Parse(r.Header.Get("X-Forwarded-Uri"))
	}

	// Pass to mux
	s.muxer.ServeHTTP(w, r)
}

// AllowHandler Allows requests
func (s *Server) AllowHandler(rule string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.logger(r, "Allow", rule, "Allowing request")
		w.WriteHeader(200)
	}
}

// AuthHandler Authenticates requests
func (s *Server) AuthHandler(providerName, rule string) http.HandlerFunc {
	p, _ := config.GetConfiguredProvider(providerName)

	return func(w http.ResponseWriter, r *http.Request) {
		// Logging setup
		logger := s.logger(r, "Auth", rule, "Authenticating request")

		// First check session cookie (for cross-domain auth)
		if sessionID := GetSessionID(r); sessionID != "" {
			// Check if this is a temporary cookie ID that needs to be unified
			if mainCookieID, isTemp := sessionStore.GetTempMapping(sessionID); isTemp {
				logger.WithFields(logrus.Fields{
					"temp_cookie_id": sessionID,
					"main_cookie_id": mainCookieID,
				}).Debug("Detected temporary cookie ID, unifying with 307 redirect")

				// Return 307 redirect to unify cookie_id
				http.SetCookie(w, MakeSessionCookie(r, mainCookieID))

				// Delete the temporary mapping
				sessionStore.DeleteTempMapping(sessionID)

				// Redirect to the same URL
				redirectURL := returnUrl(r)
				http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
				return
			}

			// Check if session exists with this cookie_id
			if session, ok := sessionStore.Get(sessionID); ok {
				// Session exists and has email, user is authenticated
				logger.WithField("email", session.Email).Debug("Valid session found")
				w.Header().Set("X-Forwarded-User", session.Email)
				w.WriteHeader(200)
				return
			}
		}

		// Not authenticated, start auth flow
		s.authRedirect(logger, w, r, p)
	}
}

// AuthCallbackHandler Handles auth callback request
func (s *Server) AuthCallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Logging setup
		logger := s.logger(r, "AuthCallback", "default", "Handling callback")

		// Check if this is a start request (cross-domain auth flow)
		if r.URL.Query().Get("action") == "start" {
			s.handleAuthStart(logger, w, r)
			return
		}

		// Check if user is already logged in on AUTH_HOST (before exchange code)
		// This handles the case where multiple tabs all go to Logto and authorize
		if authCookieID := GetSessionID(r); authCookieID != "" {
			if session, ok := sessionStore.Get(authCookieID); ok && session.Email != "" {
				logger.WithField("auth_cookie_id", authCookieID).Info("User already logged in, skipping code exchange")

				// Get state to extract redirect URL
				state := r.URL.Query().Get("state")
				if state == "" {
					logger.Warn("Missing state parameter")
					http.Error(w, "Not authorized", 401)
					return
				}

				// Try to parse as cross-domain state (session_id:redirect)
				if idx := strings.Index(state, ":http"); idx > 0 {
					redirect := state[idx+1:]
					logger.WithField("redirect", redirect).Debug("Redirecting already logged in user")
					http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
					return
				}

				// Same-domain flow: validate CSRF cookie and get redirect
				if err := ValidateState(state); err == nil {
					if c, err := FindCSRFCookie(r, state); err == nil {
						if valid, _, redirect, _, err := ValidateCSRFCookie(c, state); valid && err == nil {
							http.SetCookie(w, ClearCSRFCookie(r, c))
							logger.WithField("redirect", redirect).Debug("Redirecting already logged in user")
							http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
							return
						}
					}
				}

				// Fallback: redirect to root
				http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
				return
			}
		}

		// Get state from callback
		state := r.URL.Query().Get("state")
		if state == "" {
			logger.Warn("Missing state parameter")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Try to parse as cross-domain state (session_id:redirect)
		// Cross-domain state format: session_id:https://...
		if idx := strings.Index(state, ":http"); idx > 0 {
			sessionID := state[:idx]
			redirect := state[idx+1:]

			logger.WithFields(logrus.Fields{
				"state":      state,
				"session_id": sessionID,
				"redirect":   redirect,
			}).Info("Parsing cross-domain state")

			// Verify session exists
			if _, ok := sessionStore.Get(sessionID); !ok {
				logger.WithField("session_id", sessionID).Warn("Session expired or invalid")

				// Session expired, redirect back to application
				// The application will detect no auth and restart the flow
				http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
				return
			}

			// Get default provider
			p, err := config.GetConfiguredProvider(config.DefaultProvider)
			if err != nil {
				logger.WithField("error", err).Warn("Invalid provider")
				http.Error(w, "Not authorized", 401)
				return
			}

			// Exchange code for token
			token, err := p.ExchangeCode(redirectUri(r), r.URL.Query().Get("code"))
			if err != nil {
				logger.WithField("error", err).Error("Code exchange failed with provider")
				http.Error(w, "Service unavailable", 503)
				return
			}

			// Get user
			user, err := p.GetUser(token)
			if err != nil {
				logger.WithField("error", err).Error("Error getting user")
				http.Error(w, "Service unavailable", 503)
				return
			}

			// Update session with email and claims
			sessionStore.SetWithClaims(sessionID, user.Email, config.Lifetime, user.Claims)

			// Also set session cookie on AUTH_HOST domain (same cookie_id)
			http.SetCookie(w, MakeSessionCookie(r, sessionID))

			// Clear auth flow and broadcast SSE event
			s.authTracker.Clear()
			s.waitingMutex.Lock()
			s.waitingCount = 0
			s.waitingMutex.Unlock()
			s.ssePool.Broadcast("authenticated")

			logger.WithField("sse_connections", s.ssePool.Count()).Info("Auth flow completed, broadcasted SSE event")

			// Log user login (cross-domain flow)
			log.WithFields(logrus.Fields{
				"host":          r.Host,
				"user.name":     getClaimString(user.Claims, "name"),
				"user.username": getClaimStringMulti(user.Claims, "preferred_username", "username"),
				"user.phone":    getClaimString(user.Claims, "phone_number"),
				"user.sub":      getClaimString(user.Claims, "sub"),
				"source_ip":     r.Header.Get("X-Forwarded-For"),
			}).Info("User logged in")

			logger.WithFields(logrus.Fields{
				"redirect":   redirect,
				"session_id": sessionID,
			}).Debug("Cross-domain auth: updated session and set cookie on AUTH_HOST, redirecting back")

			http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
			return
		}

		// Same-domain flow: validate CSRF cookie
		if err := ValidateState(state); err != nil {
			logger.WithFields(logrus.Fields{
				"error": err,
			}).Warn("Error validating state")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Check for CSRF cookie
		c, err := FindCSRFCookie(r, state)
		if err != nil {
			logger.Info("Missing csrf cookie")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Validate CSRF cookie against state
		valid, providerName, redirect, _, err := ValidateCSRFCookie(c, state)
		if !valid {
			logger.WithFields(logrus.Fields{
				"error":       err,
				"csrf_cookie": c,
			}).Warn("Error validating csrf cookie")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Get provider
		p, err := config.GetConfiguredProvider(providerName)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"error":       err,
				"csrf_cookie": c,
				"provider":    providerName,
			}).Warn("Invalid provider in csrf cookie")
			http.Error(w, "Not authorized", 401)
			return
		}

		// Clear CSRF cookie
		http.SetCookie(w, ClearCSRFCookie(r, c))

		// Exchange code for token
		token, err := p.ExchangeCode(redirectUri(r), r.URL.Query().Get("code"))
		if err != nil {
			logger.WithField("error", err).Error("Code exchange failed with provider")
			http.Error(w, "Service unavailable", 503)
			return
		}

		// Get user
		user, err := p.GetUser(token)
		if err != nil {
			logger.WithField("error", err).Error("Error getting user")
			http.Error(w, "Service unavailable", 503)
			return
		}

		// Generate session ID and create session
		sessionID, err := GenerateSessionID()
		if err != nil {
			logger.WithField("error", err).Error("Error generating session ID")
			http.Error(w, "Service unavailable", 503)
			return
		}

		// Create session with user email and claims
		sessionStore.SetWithClaims(sessionID, user.Email, config.Lifetime, user.Claims)

		// Set session cookie (same format as cross-domain)
		http.SetCookie(w, MakeSessionCookie(r, sessionID))

		// Clear auth flow and broadcast SSE event (for same-domain multi-tab scenario)
		s.authTracker.Clear()
		s.waitingMutex.Lock()
		s.waitingCount = 0
		s.waitingMutex.Unlock()
		s.ssePool.Broadcast("authenticated")

		logger.WithField("sse_connections", s.ssePool.Count()).Info("Auth flow completed, broadcasted SSE event")

		// Log user login (same-domain flow)
		log.WithFields(logrus.Fields{
			"host":          r.Host,
			"user.name":     getClaimString(user.Claims, "name"),
			"user.username": getClaimStringMulti(user.Claims, "preferred_username", "username"),
			"user.phone":    getClaimString(user.Claims, "phone_number"),
			"user.sub":      getClaimString(user.Claims, "sub"),
			"source_ip":     r.Header.Get("X-Forwarded-For"),
		}).Info("User logged in")

		logger.WithFields(logrus.Fields{
			"provider":   providerName,
			"redirect":   redirect,
			"session_id": sessionID,
		}).Debug("Successfully generated session cookie, redirecting user.")

		// Redirect
		http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
	}
}

// handleAuthStart handles the start of cross-domain auth flow
// Supports multi-tab authentication with waiting page
func (s *Server) handleAuthStart(logger *logrus.Entry, w http.ResponseWriter, r *http.Request) {
	providerName := r.URL.Query().Get("provider")
	redirect := r.URL.Query().Get("redirect")
	sessionID := r.URL.Query().Get("session_id")
	force := r.URL.Query().Get("force") // User clicked "login myself" button

	if providerName == "" || redirect == "" || sessionID == "" {
		logger.Warn("Missing parameters in auth start request")
		http.Error(w, "Bad request", 400)
		return
	}

	// Check if user is already logged in on AUTH_HOST
	if authCookieID := GetSessionID(r); authCookieID != "" {
		if session, ok := sessionStore.Get(authCookieID); ok {
			// Session exists on AUTH_HOST
			if session.Email != "" {
				// User is already logged in
				// Extract target host from redirect URL
				targetHost := redirect
				if redirectURL, err := url.Parse(redirect); err == nil {
					targetHost = redirectURL.Host
				}

				// Log cross-domain access
				log.WithFields(logrus.Fields{
					"host":          targetHost,
					"user.name":     getClaimString(session.Claims, "name"),
					"user.username": getClaimStringMulti(session.Claims, "preferred_username", "username"),
					"user.phone":    getClaimString(session.Claims, "phone_number"),
					"user.sub":      getClaimString(session.Claims, "sub"),
					"source_ip":     r.Header.Get("X-Forwarded-For"),
				}).Info("User accessed from new domain")

				logger.WithFields(logrus.Fields{
					"auth_cookie_id": authCookieID,
					"temp_cookie_id": sessionID,
				}).Debug("User already logged in, creating temp mapping")

				// Update the temp session with email
				sessionStore.Set(sessionID, session.Email, config.Lifetime)

				// Create temporary mapping: temp_cookie_id -> main_cookie_id
				sessionStore.SetTempMapping(sessionID, authCookieID)

				// Redirect back to original domain
				http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
				return
			} else {
				// Session exists but email is empty, meaning auth flow is in progress
				// This is a subsequent tab, return waiting page
				logger.WithField("auth_cookie_id", authCookieID).Info("Auth flow in progress (empty session), returning waiting page")

				// Create temporary mapping for later unification
				sessionStore.SetTempMapping(sessionID, authCookieID)

				// Return waiting page
				s.returnWaitingPage(w, r, redirect)
				return
			}
		}
	}

	// Get provider
	p, err := config.GetConfiguredProvider(providerName)
	if err != nil {
		logger.WithField("error", err).Warn("Invalid provider")
		http.Error(w, "Bad request", 400)
		return
	}

	// Check if force login (user clicked "login myself" button)
	if force == "true" {
		logger.Info("Force login requested, redirecting to Logto")

		// Build state: session_id:redirect
		state := fmt.Sprintf("%s:%s", sessionID, redirect)

		// Redirect to provider login
		loginURL := p.GetLoginURL(redirectUri(r), state)
		http.Redirect(w, r, loginURL, http.StatusTemporaryRedirect)
		return
	}

	// Multi-tab logic: check if auth flow is in progress
	if s.authTracker.IsInProgress() {
		// Auth flow already in progress, return waiting page
		requestNum := s.authTracker.Start()

		logger.WithField("request_number", requestNum).Info("Auth flow in progress, returning waiting page")

		// Return waiting page with SSE
		s.returnWaitingPage(w, r, redirect)
		return
	}

	// No auth flow in progress, this is the first request
	if s.authTracker.IsTimeout() {
		// Previous flow timed out, clear it
		s.authTracker.Clear()
	}

	// Start auth flow and redirect first request to Logto
	requestNum := s.authTracker.Start()

	logger.WithField("request_number", requestNum).Info("First request, redirecting to Logto")

	// Build state: session_id:redirect
	state := fmt.Sprintf("%s:%s", sessionID, redirect)

	// Redirect to provider login
	loginURL := p.GetLoginURL(redirectUri(r), state)
	http.Redirect(w, r, loginURL, http.StatusTemporaryRedirect)
}

// returnWaitingPage returns the waiting page HTML
func (s *Server) returnWaitingPage(w http.ResponseWriter, r *http.Request, redirect string) {
	// Build SSE URL
	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		proto = "https"
	}
	sseURL := fmt.Sprintf("%s://%s%s/wait", proto, r.Host, config.Path)

	// Build force login URL (for "login myself" button)
	providerName := r.URL.Query().Get("provider")
	sessionID := r.URL.Query().Get("session_id")
	forceLoginURL := fmt.Sprintf("%s://%s%s?force=true&action=start&provider=%s&redirect=%s&session_id=%s",
		proto, r.Host, config.Path,
		url.QueryEscape(providerName),
		url.QueryEscape(redirect),
		url.QueryEscape(sessionID))

	// Replace placeholders in HTML
	html := strings.ReplaceAll(waitingPageHTML, "{{.RedirectURL}}", redirect)
	html = strings.ReplaceAll(html, "{{.SSEURL}}", sseURL)
	html = strings.ReplaceAll(html, "{{.ForceLoginURL}}", forceLoginURL)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte(html))
}

// LogoutHandler logs a user out
func (s *Server) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Log user logout
		log.WithFields(logrus.Fields{
			"host": r.Host,
		}).Info("User logged out")

		// Clear cookie
		http.SetCookie(w, ClearCookie(r))

		logger := s.logger(r, "Logout", "default", "Handling logout")
		logger.Debug("Logged out user")

		if config.LogoutRedirect != "" {
			http.Redirect(w, r, config.LogoutRedirect, http.StatusTemporaryRedirect)
		} else {
			http.Error(w, "You have been logged out", 401)
		}
	}
}

// SSEWaitHandler handles SSE connections for waiting pages
func (s *Server) SSEWaitHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := s.logger(r, "SSEWait", "default", "Handling SSE wait connection")

		// Set SSE headers
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		// Generate connection ID
		connID, err := GenerateSessionID()
		if err != nil {
			logger.WithField("error", err).Error("Error generating connection ID")
			http.Error(w, "Internal server error", 500)
			return
		}

		// Create event channel
		eventChan := make(chan string, 10)

		// Add to connection pool
		s.ssePool.AddConnection(connID, eventChan)
		defer s.ssePool.RemoveConnection(connID)

		logger.WithField("connection_id", connID).Info("SSE connection established")

		// Get flusher
		flusher, ok := w.(http.Flusher)
		if !ok {
			logger.Error("Streaming not supported")
			http.Error(w, "Streaming not supported", 500)
			return
		}

		// Send initial comment
		fmt.Fprintf(w, ": connected\n\n")
		flusher.Flush()

		// Heartbeat ticker (every 30 seconds)
		heartbeat := time.NewTicker(30 * time.Second)
		defer heartbeat.Stop()

		// Timeout (30 minutes)
		timeout := time.After(30 * time.Minute)

		// Event loop
		for {
			select {
			case event := <-eventChan:
				// Send event
				fmt.Fprintf(w, "event: %s\n", event)
				fmt.Fprintf(w, "data: {\"event\": \"%s\"}\n\n", event)
				flusher.Flush()

				if event == "authenticated" {
					logger.Info("Sent authenticated event, closing connection")
					return
				}

			case <-heartbeat.C:
				// Send heartbeat
				fmt.Fprintf(w, "event: heartbeat\n")
				fmt.Fprintf(w, "data: {\"event\": \"heartbeat\"}\n\n")
				flusher.Flush()

			case <-timeout:
				// Timeout
				logger.Info("SSE connection timeout")
				return

			case <-r.Context().Done():
				// Client disconnected
				logger.Info("SSE connection closed by client")
				return
			}
		}
	}
}

// DebugHandler returns current user info and all ID token claims
func (s *Server) DebugHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := s.logger(r, "Debug", "default", "Handling debug request")

		// Get session ID from cookie
		sessionID := GetSessionID(r)
		if sessionID == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(401)
			w.Write([]byte(`{"error": "Not authenticated", "message": "No session cookie found"}`))
			return
		}

		// Get session
		session, ok := sessionStore.Get(sessionID)
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(401)
			w.Write([]byte(`{"error": "Session not found", "session_id": "` + sessionID + `"}`))
			return
		}

		// Build response with all claims
		response := map[string]interface{}{
			"authenticated": true,
			"session_id":    sessionID,
			"email":         session.Email,
			"created_at":    session.CreatedAt.Format(time.RFC3339),
			"expires_at":    session.ExpiresAt.Format(time.RFC3339),
			"claims":        session.Claims,
		}

		// Convert to JSON
		jsonBytes, err := json.Marshal(response)
		if err != nil {
			logger.WithField("error", err).Error("Error marshaling response")
			http.Error(w, "Internal server error", 500)
			return
		}

		// Return response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(jsonBytes)

		logger.WithFields(logrus.Fields{
			"session_id":   sessionID,
			"email":        session.Email,
			"claims_count": len(session.Claims),
		}).Info("Debug info returned")
	}
}

func (s *Server) authRedirect(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, p provider.Provider) {
	// Check if we need to redirect to AUTH_HOST first (cross-domain scenario)
	if config.AuthHost != "" && r.Host != config.AuthHost {
		// Generate session ID and set session cookie on current domain
		sessionID, err := GenerateSessionID()
		if err != nil {
			logger.WithField("error", err).Error("Error generating session ID")
			http.Error(w, "Service unavailable", 503)
			return
		}

		// Create empty session (will be filled with email after auth)
		sessionStore.Set(sessionID, "", config.Lifetime)

		// Set session cookie on current domain
		http.SetCookie(w, MakeSessionCookie(r, sessionID))

		// Cross-domain: redirect to AUTH_HOST with session_id in URL
		proto := r.Header.Get("X-Forwarded-Proto")
		if proto == "" {
			proto = "https"
		}
		startURL := fmt.Sprintf("%s://%s%s?action=start&provider=%s&redirect=%s&session_id=%s",
			proto,
			config.AuthHost,
			config.Path,
			url.QueryEscape(p.Name()),
			url.QueryEscape(returnUrl(r)),
			url.QueryEscape(sessionID),
		)
		http.Redirect(w, r, startURL, http.StatusTemporaryRedirect)
		logger.WithFields(logrus.Fields{
			"start_url":  startURL,
			"session_id": sessionID,
		}).Debug("Cross-domain: set session cookie and redirected to AUTH_HOST")
		return
	}

	// Same domain or no AUTH_HOST: use traditional CSRF cookie flow
	err, nonce := Nonce()
	if err != nil {
		logger.WithField("error", err).Error("Error generating nonce")
		http.Error(w, "Service unavailable", 503)
		return
	}

	csrf := MakeCSRFCookie(r, nonce)
	http.SetCookie(w, csrf)

	if !config.InsecureCookie && r.Header.Get("X-Forwarded-Proto") != "https" {
		logger.Warn("You are using \"secure\" cookies for a request that was not " +
			"received via https. You should either redirect to https or pass the " +
			"\"insecure-cookie\" config option to permit cookies via http.")
	}

	// Forward them on
	loginURL := p.GetLoginURL(redirectUri(r), MakeState(r, p, nonce))
	http.Redirect(w, r, loginURL, http.StatusTemporaryRedirect)

	logger.WithFields(logrus.Fields{
		"csrf_cookie": csrf,
		"login_url":   loginURL,
	}).Debug("Set CSRF cookie and redirected to provider login url")
}

func (s *Server) logger(r *http.Request, handler, rule, msg string) *logrus.Entry {
	// Create logger
	logger := log.WithFields(logrus.Fields{
		"handler":   handler,
		"rule":      rule,
		"method":    r.Header.Get("X-Forwarded-Method"),
		"proto":     r.Header.Get("X-Forwarded-Proto"),
		"host":      r.Header.Get("X-Forwarded-Host"),
		"uri":       r.Header.Get("X-Forwarded-Uri"),
		"source_ip": r.Header.Get("X-Forwarded-For"),
	})

	// Log request
	logger.WithFields(logrus.Fields{
		"cookies": r.Cookies(),
	}).Debug(msg)

	return logger
}

// getClaimString extracts a string claim from claims map
func getClaimString(claims map[string]interface{}, key string) string {
	if claims == nil {
		return ""
	}
	if val, ok := claims[key].(string); ok {
		return val
	}
	return ""
}

// getClaimStringMulti tries multiple keys and returns the first non-empty value
func getClaimStringMulti(claims map[string]interface{}, keys ...string) string {
	if claims == nil {
		return ""
	}
	for _, key := range keys {
		if val, ok := claims[key].(string); ok && val != "" {
			return val
		}
	}
	return ""
}
