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

// SessionStore stores sessions in memory
type SessionStore struct {
	sessions map[string]*Session
	mu       sync.RWMutex
}

// Global session store
var sessionStore = &SessionStore{
	sessions: make(map[string]*Session),
}

// Set stores a session
func (s *SessionStore) Set(sessionID, email string, lifetime time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sessions[sessionID] = &Session{
		Email:     email,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(lifetime),
	}
}

// Get retrieves a session
func (s *SessionStore) Get(sessionID string) (*Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, ok := s.sessions[sessionID]
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
func (s *SessionStore) Delete(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
}

// Cleanup removes expired sessions (call periodically)
func (s *SessionStore) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for id, session := range s.sessions {
		if now.After(session.ExpiresAt) {
			delete(s.sessions, id)
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
