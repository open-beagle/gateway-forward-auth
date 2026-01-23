package tfa

import (
	"sync"
	"time"
)

// Session represents a user session
type Session struct {
	Email     string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// TempMapping represents a temporary cookie ID mapping
type TempMapping struct {
	MainCookieID string
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

// SessionStore stores sessions in memory
type SessionStore struct {
	sessions     map[string]*Session
	tempMappings map[string]*TempMapping
	mu           sync.RWMutex
}

// Global session store
var sessionStore = &SessionStore{
	sessions:     make(map[string]*Session),
	tempMappings: make(map[string]*TempMapping),
}

// Set stores a session (cookie_id is used as session_id directly)
func (s *SessionStore) Set(cookieID, email string, lifetime time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sessions[cookieID] = &Session{
		Email:     email,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(lifetime),
	}
}

// Get retrieves a session by cookie_id
func (s *SessionStore) Get(cookieID string) (*Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, ok := s.sessions[cookieID]
	if !ok {
		return nil, false
	}

	// Check if expired
	if time.Now().After(session.ExpiresAt) {
		return nil, false
	}

	return session, true
}

// Delete removes a session
func (s *SessionStore) Delete(cookieID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, cookieID)
}

// SetTempMapping stores a temporary cookie ID mapping
// Maps temp_cookie_id -> main_cookie_id for 5 minutes
func (s *SessionStore) SetTempMapping(tempCookieID, mainCookieID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tempMappings[tempCookieID] = &TempMapping{
		MainCookieID: mainCookieID,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(5 * time.Minute),
	}
}

// GetTempMapping retrieves the main cookie ID for a temp cookie ID
func (s *SessionStore) GetTempMapping(tempCookieID string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	mapping, ok := s.tempMappings[tempCookieID]
	if !ok {
		return "", false
	}

	// Check if expired
	if time.Now().After(mapping.ExpiresAt) {
		return "", false
	}

	return mapping.MainCookieID, true
}

// DeleteTempMapping removes a temporary mapping
func (s *SessionStore) DeleteTempMapping(tempCookieID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tempMappings, tempCookieID)
}

// IsTempMapping checks if a cookie ID is a temporary mapping
func (s *SessionStore) IsTempMapping(cookieID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.tempMappings[cookieID]
	return ok
}

// Cleanup removes expired sessions and temp mappings (call periodically)
func (s *SessionStore) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	// Clean up expired sessions
	for id, session := range s.sessions {
		if now.After(session.ExpiresAt) {
			delete(s.sessions, id)
		}
	}

	// Clean up expired temp mappings
	for id, mapping := range s.tempMappings {
		if now.After(mapping.ExpiresAt) {
			delete(s.tempMappings, id)
		}
	}
}

// StartCleanup starts a goroutine to periodically clean up expired sessions
func (s *SessionStore) StartCleanup(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		for range ticker.C {
			s.Cleanup()
		}
	}()
}

// StartSessionCleanup starts the global session store cleanup
func StartSessionCleanup(interval time.Duration) {
	sessionStore.StartCleanup(interval)
}
