package main

import (
	"testing"
	"time"
)

func TestSessionManagerLifecycle(t *testing.T) {
	t.Parallel()

	manager := NewSessionManager("secret-password", 10*time.Millisecond)
	if !manager.Authenticate("secret-password") {
		t.Fatal("Authenticate() = false, want true")
	}
	if manager.Authenticate("wrong-password") {
		t.Fatal("Authenticate() = true for wrong password")
	}

	token := manager.Create()
	if token == "" {
		t.Fatal("Create() returned empty token")
	}
	if !manager.Valid(token) {
		t.Fatal("Valid() = false immediately after Create()")
	}

	manager.Destroy(token)
	if manager.Valid(token) {
		t.Fatal("Valid() = true after Destroy()")
	}

	expiring := manager.Create()
	time.Sleep(20 * time.Millisecond)
	if manager.Valid(expiring) {
		t.Fatal("Valid() = true after session expiry")
	}
}
