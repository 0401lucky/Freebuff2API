package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"sync"
	"time"
)

const sessionCookieName = "freebuff_session"

type sessionRecord struct {
	ID        string
	ExpiresAt time.Time
}

type SessionManager struct {
	password string
	ttl      time.Duration

	mu       sync.Mutex
	sessions map[string]sessionRecord
}

func NewSessionManager(password string, ttl time.Duration) *SessionManager {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &SessionManager{
		password: password,
		ttl:      ttl,
		sessions: make(map[string]sessionRecord),
	}
}

func (m *SessionManager) Enabled() bool {
	return m != nil && m.password != ""
}

func (m *SessionManager) Authenticate(password string) bool {
	if !m.Enabled() {
		return false
	}
	expected := []byte(m.password)
	provided := []byte(password)
	if len(expected) != len(provided) {
		return false
	}
	return subtle.ConstantTimeCompare(expected, provided) == 1
}

func (m *SessionManager) Create() string {
	if !m.Enabled() {
		return ""
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupLocked()

	token := randomSessionID()
	m.sessions[token] = sessionRecord{
		ID:        token,
		ExpiresAt: time.Now().Add(m.ttl),
	}
	return token
}

func (m *SessionManager) Valid(token string) bool {
	if !m.Enabled() || token == "" {
		return false
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	record, ok := m.sessions[token]
	if !ok {
		return false
	}
	if time.Now().After(record.ExpiresAt) {
		delete(m.sessions, token)
		return false
	}

	record.ExpiresAt = time.Now().Add(m.ttl)
	m.sessions[token] = record
	return true
}

func (m *SessionManager) Destroy(token string) {
	if !m.Enabled() || token == "" {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, token)
}

func (m *SessionManager) cleanupLocked() {
	now := time.Now()
	for token, record := range m.sessions {
		if now.After(record.ExpiresAt) {
			delete(m.sessions, token)
		}
	}
}

func randomSessionID() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return hex.EncodeToString([]byte(time.Now().Format(time.RFC3339Nano)))
	}
	return hex.EncodeToString(buf)
}
