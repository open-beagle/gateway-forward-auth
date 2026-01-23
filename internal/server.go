package tfa

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/thomseddon/traefik-forward-auth/internal/provider"
	muxhttp "github.com/traefik/traefik/v2/pkg/muxer/http"
)

// Server contains muxer and handler methods
type Server struct {
	muxer *muxhttp.Muxer
}

// NewServer creates a new server object and builds muxer
func NewServer() *Server {
	s := &Server{}
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

		// Then check auth cookie (legacy/same-domain)
		c, err := r.Cookie(config.CookieName)
		if err == nil {
			email, err := ValidateCookie(r, c)
			if err == nil {
				valid := ValidateEmail(email, rule)
				if valid {
					logger.Debug("Allowing valid request")
					w.Header().Set("X-Forwarded-User", email)
					w.WriteHeader(200)
					return
				}
				logger.WithField("email", email).Warn("Invalid email")
				http.Error(w, "Not authorized", 401)
				return
			}
			if err.Error() != "Cookie has expired" {
				logger.WithField("error", err).Warn("Invalid cookie")
				http.Error(w, "Not authorized", 401)
				return
			}
			logger.Info("Cookie has expired")
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

			// Verify session exists
			if _, ok := sessionStore.Get(sessionID); !ok {
				logger.WithField("session_id", sessionID).Warn("Session expired or invalid, restarting auth flow")

				// Get default provider and restart auth flow
				p, err := config.GetConfiguredProvider(config.DefaultProvider)
				if err != nil {
					logger.WithField("error", err).Warn("Invalid provider")
					http.Error(w, "Not authorized", 401)
					return
				}

				// Restart authentication flow
				s.authRedirect(logger, w, r, p)
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

			// Update session with email
			sessionStore.Set(sessionID, user.Email, config.Lifetime)

			// Also set session cookie on AUTH_HOST domain (same cookie_id)
			http.SetCookie(w, MakeSessionCookie(r, sessionID))

			logger.WithFields(logrus.Fields{
				"redirect":   redirect,
				"user":       user.Email,
				"session_id": sessionID,
			}).Info("Cross-domain auth: updated session and set cookie on AUTH_HOST, redirecting back")

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

		// Same domain: set cookie directly
		http.SetCookie(w, MakeCookie(r, user.Email))
		logger.WithFields(logrus.Fields{
			"provider": providerName,
			"redirect": redirect,
			"user":     user.Email,
		}).Info("Successfully generated auth cookie, redirecting user.")

		// Redirect
		http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
	}
}

// handleAuthStart handles the start of cross-domain auth flow
// Redirects directly to provider (no CSRF cookie needed, session_id serves as CSRF token)
func (s *Server) handleAuthStart(logger *logrus.Entry, w http.ResponseWriter, r *http.Request) {
	providerName := r.URL.Query().Get("provider")
	redirect := r.URL.Query().Get("redirect")
	sessionID := r.URL.Query().Get("session_id")

	if providerName == "" || redirect == "" || sessionID == "" {
		logger.Warn("Missing parameters in auth start request")
		http.Error(w, "Bad request", 400)
		return
	}

	// Check if user is already logged in on AUTH_HOST
	if authCookieID := GetSessionID(r); authCookieID != "" {
		if session, ok := sessionStore.Get(authCookieID); ok && session.Email != "" {
			// User is already logged in on AUTH_HOST
			logger.WithFields(logrus.Fields{
				"auth_cookie_id": authCookieID,
				"temp_cookie_id": sessionID,
				"email":          session.Email,
			}).Info("User already logged in, creating temp mapping")

			// Update the temp session with email
			sessionStore.Set(sessionID, session.Email, config.Lifetime)

			// Create temporary mapping: temp_cookie_id -> main_cookie_id
			sessionStore.SetTempMapping(sessionID, authCookieID)

			// Redirect back to original domain
			http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
			return
		}
	}

	// Get provider
	p, err := config.GetConfiguredProvider(providerName)
	if err != nil {
		logger.WithField("error", err).Warn("Invalid provider")
		http.Error(w, "Bad request", 400)
		return
	}

	// Build state: session_id:redirect
	state := fmt.Sprintf("%s:%s", sessionID, redirect)

	// Redirect directly to provider login (no CSRF cookie needed)
	loginURL := p.GetLoginURL(redirectUri(r), state)
	http.Redirect(w, r, loginURL, http.StatusTemporaryRedirect)

	logger.WithFields(logrus.Fields{
		"login_url":  loginURL,
		"session_id": sessionID,
		"redirect":   redirect,
	}).Debug("Redirected to provider login")
}

// LogoutHandler logs a user out
func (s *Server) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Clear cookie
		http.SetCookie(w, ClearCookie(r))

		logger := s.logger(r, "Logout", "default", "Handling logout")
		logger.Info("Logged out user")

		if config.LogoutRedirect != "" {
			http.Redirect(w, r, config.LogoutRedirect, http.StatusTemporaryRedirect)
		} else {
			http.Error(w, "You have been logged out", 401)
		}
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
