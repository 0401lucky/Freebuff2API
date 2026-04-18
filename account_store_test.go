package main

import (
	"context"
	"strings"
	"testing"
)

func TestAccountStoreCRUDAndEncryption(t *testing.T) {
	t.Parallel()

	store, err := OpenAccountStore(t.TempDir()+"\\accounts.db", NewTokenCipher("unit-test-secret"))
	if err != nil {
		t.Fatalf("OpenAccountStore() error = %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	ctx := context.Background()
	record, err := store.Create(ctx, AccountInput{
		Label:    "主账号",
		Token:    "secret-token-123456",
		Enabled:  true,
		Priority: 120,
		Weight:   3,
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	var ciphertext string
	if err := store.db.QueryRowContext(ctx, `SELECT token_ciphertext FROM accounts WHERE id = ?`, record.ID).Scan(&ciphertext); err != nil {
		t.Fatalf("scan ciphertext error = %v", err)
	}
	if ciphertext == record.Token || strings.Contains(ciphertext, record.Token) {
		t.Fatalf("ciphertext leaked plaintext token: %q", ciphertext)
	}

	records, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("List() len = %d, want 1", len(records))
	}
	if records[0].Token != "secret-token-123456" {
		t.Fatalf("List() token = %q, want decrypted token", records[0].Token)
	}

	newLabel := "备用账号"
	newWeight := 5
	updated, err := store.Update(ctx, record.ID, AccountUpdateInput{
		Label:  &newLabel,
		Weight: &newWeight,
	})
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	if updated.Label != newLabel || updated.Weight != newWeight {
		t.Fatalf("Update() = %+v, want label=%q weight=%d", updated, newLabel, newWeight)
	}

	if err := store.UpdateValidation(ctx, record.ID, accountStatusInvalid, "auth rejected", records[0].CreatedAt); err != nil {
		t.Fatalf("UpdateValidation() error = %v", err)
	}

	got, err := store.Get(ctx, record.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.LastStatus != accountStatusInvalid {
		t.Fatalf("Get().LastStatus = %q, want %q", got.LastStatus, accountStatusInvalid)
	}

	if err := store.Delete(ctx, record.ID); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	count, err := store.Count(ctx)
	if err != nil {
		t.Fatalf("Count() error = %v", err)
	}
	if count != 0 {
		t.Fatalf("Count() = %d, want 0", count)
	}
}
