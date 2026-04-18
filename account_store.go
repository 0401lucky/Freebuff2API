package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	accountStatusUnknown = "unknown"
	accountStatusHealthy = "healthy"
	accountStatusError   = "error"
	accountStatusInvalid = "invalid"
)

type TokenCipher struct {
	key [32]byte
}

func NewTokenCipher(secret string) *TokenCipher {
	return &TokenCipher{key: sha256.Sum256([]byte(strings.TrimSpace(secret)))}
}

func (c *TokenCipher) Encrypt(token string) (string, error) {
	block, err := aes.NewCipher(c.key[:])
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("read nonce: %w", err)
	}
	sealed := gcm.Seal(nil, nonce, []byte(token), nil)
	encoded := append(nonce, sealed...)
	return base64.StdEncoding.EncodeToString(encoded), nil
}

func (c *TokenCipher) Decrypt(payload string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(payload))
	if err != nil {
		return "", fmt.Errorf("decode token payload: %w", err)
	}

	block, err := aes.NewCipher(c.key[:])
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create gcm: %w", err)
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("token payload too short")
	}

	nonce := raw[:gcm.NonceSize()]
	ciphertext := raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt token: %w", err)
	}
	return string(plain), nil
}

type AccountRecord struct {
	ID            string
	Label         string
	Token         string
	TokenPreview  string
	Enabled       bool
	Priority      int
	Weight        int
	LastStatus    string
	LastError     string
	LastCheckedAt time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type AccountInput struct {
	Label    string
	Token    string
	Enabled  bool
	Priority int
	Weight   int
}

type AccountUpdateInput struct {
	Label    *string
	Token    *string
	Enabled  *bool
	Priority *int
	Weight   *int
}

type AccountStore struct {
	db     *sql.DB
	cipher *TokenCipher
}

func OpenAccountStore(dbPath string, cipher *TokenCipher) (*AccountStore, error) {
	if strings.TrimSpace(dbPath) == "" {
		return nil, errors.New("database path cannot be empty")
	}
	if cipher == nil {
		return nil, errors.New("token cipher is required")
	}

	absPath, err := filepath.Abs(dbPath)
	if err != nil {
		return nil, fmt.Errorf("resolve database path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}

	db, err := sql.Open("sqlite", absPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}

	store := &AccountStore{db: db, cipher: cipher}
	if err := store.initSchema(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *AccountStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *AccountStore) initSchema(ctx context.Context) error {
	statements := []string{
		`PRAGMA journal_mode = WAL;`,
		`PRAGMA busy_timeout = 5000;`,
		`CREATE TABLE IF NOT EXISTS accounts (
			id TEXT PRIMARY KEY,
			label TEXT NOT NULL,
			token_ciphertext TEXT NOT NULL,
			token_preview TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			priority INTEGER NOT NULL DEFAULT 100,
			weight INTEGER NOT NULL DEFAULT 1,
			last_status TEXT NOT NULL DEFAULT 'unknown',
			last_error TEXT NOT NULL DEFAULT '',
			last_checked_at TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
	}

	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("init schema: %w", err)
		}
	}
	return nil
}

func (s *AccountStore) Count(ctx context.Context) (int, error) {
	row := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM accounts`)
	var count int
	if err := row.Scan(&count); err != nil {
		return 0, fmt.Errorf("count accounts: %w", err)
	}
	return count, nil
}

func (s *AccountStore) List(ctx context.Context) ([]AccountRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, label, token_ciphertext, token_preview, enabled, priority, weight,
		       last_status, last_error, last_checked_at, created_at, updated_at
		FROM accounts
		ORDER BY enabled DESC, priority DESC, weight DESC, created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}
	defer rows.Close()

	var accounts []AccountRecord
	for rows.Next() {
		record, err := s.scanAccount(rows)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate accounts: %w", err)
	}
	return accounts, nil
}

func (s *AccountStore) Get(ctx context.Context, id string) (AccountRecord, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, label, token_ciphertext, token_preview, enabled, priority, weight,
		       last_status, last_error, last_checked_at, created_at, updated_at
		FROM accounts
		WHERE id = ?`, strings.TrimSpace(id))
	record, err := s.scanAccount(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AccountRecord{}, fmt.Errorf("account %q not found", id)
		}
		return AccountRecord{}, err
	}
	return record, nil
}

func (s *AccountStore) Create(ctx context.Context, input AccountInput) (AccountRecord, error) {
	record, err := normalizeAccountInput(input)
	if err != nil {
		return AccountRecord{}, err
	}

	now := time.Now().UTC()
	record.ID = newAccountID()
	record.CreatedAt = now
	record.UpdatedAt = now
	record.LastStatus = accountStatusUnknown
	record.LastCheckedAt = time.Time{}

	ciphertext, err := s.cipher.Encrypt(record.Token)
	if err != nil {
		return AccountRecord{}, err
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO accounts (
			id, label, token_ciphertext, token_preview, enabled, priority, weight,
			last_status, last_error, last_checked_at, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.ID,
		record.Label,
		ciphertext,
		record.TokenPreview,
		boolToInt(record.Enabled),
		record.Priority,
		record.Weight,
		record.LastStatus,
		record.LastError,
		formatOptionalTime(record.LastCheckedAt),
		record.CreatedAt.Format(time.RFC3339Nano),
		record.UpdatedAt.Format(time.RFC3339Nano),
	)
	if err != nil {
		return AccountRecord{}, fmt.Errorf("insert account: %w", err)
	}
	return record, nil
}

func (s *AccountStore) Update(ctx context.Context, id string, input AccountUpdateInput) (AccountRecord, error) {
	current, err := s.Get(ctx, id)
	if err != nil {
		return AccountRecord{}, err
	}

	if input.Label != nil {
		current.Label = strings.TrimSpace(*input.Label)
	}
	if input.Token != nil {
		current.Token = strings.TrimSpace(*input.Token)
		current.TokenPreview = maskToken(current.Token)
		current.LastStatus = accountStatusUnknown
		current.LastError = ""
		current.LastCheckedAt = time.Time{}
	}
	if input.Enabled != nil {
		current.Enabled = *input.Enabled
	}
	if input.Priority != nil {
		current.Priority = *input.Priority
	}
	if input.Weight != nil {
		current.Weight = *input.Weight
	}

	if err := validateAccountRecord(current); err != nil {
		return AccountRecord{}, err
	}

	ciphertext, err := s.cipher.Encrypt(current.Token)
	if err != nil {
		return AccountRecord{}, err
	}

	current.UpdatedAt = time.Now().UTC()

	_, err = s.db.ExecContext(ctx, `
		UPDATE accounts
		SET label = ?, token_ciphertext = ?, token_preview = ?, enabled = ?, priority = ?, weight = ?,
		    last_status = ?, last_error = ?, last_checked_at = ?, updated_at = ?
		WHERE id = ?`,
		current.Label,
		ciphertext,
		current.TokenPreview,
		boolToInt(current.Enabled),
		current.Priority,
		current.Weight,
		current.LastStatus,
		current.LastError,
		formatOptionalTime(current.LastCheckedAt),
		current.UpdatedAt.Format(time.RFC3339Nano),
		current.ID,
	)
	if err != nil {
		return AccountRecord{}, fmt.Errorf("update account: %w", err)
	}
	return current, nil
}

func (s *AccountStore) Delete(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM accounts WHERE id = ?`, strings.TrimSpace(id))
	if err != nil {
		return fmt.Errorf("delete account: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete account rows affected: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("account %q not found", id)
	}
	return nil
}

func (s *AccountStore) UpdateValidation(ctx context.Context, id, status, lastError string, checkedAt time.Time) error {
	status = normalizeAccountStatus(status)
	checkedAt = checkedAt.UTC()

	result, err := s.db.ExecContext(ctx, `
		UPDATE accounts
		SET last_status = ?, last_error = ?, last_checked_at = ?, updated_at = ?
		WHERE id = ?`,
		status,
		strings.TrimSpace(lastError),
		formatOptionalTime(checkedAt),
		time.Now().UTC().Format(time.RFC3339Nano),
		strings.TrimSpace(id),
	)
	if err != nil {
		return fmt.Errorf("update validation: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("validation rows affected: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("account %q not found", id)
	}
	return nil
}

func (s *AccountStore) scanAccount(scanner interface {
	Scan(dest ...any) error
}) (AccountRecord, error) {
	var (
		record          AccountRecord
		tokenCiphertext string
		enabled         int
		lastCheckedRaw  string
		createdRaw      string
		updatedRaw      string
	)

	if err := scanner.Scan(
		&record.ID,
		&record.Label,
		&tokenCiphertext,
		&record.TokenPreview,
		&enabled,
		&record.Priority,
		&record.Weight,
		&record.LastStatus,
		&record.LastError,
		&lastCheckedRaw,
		&createdRaw,
		&updatedRaw,
	); err != nil {
		return AccountRecord{}, err
	}

	token, err := s.cipher.Decrypt(tokenCiphertext)
	if err != nil {
		return AccountRecord{}, fmt.Errorf("decrypt account %q token: %w", record.ID, err)
	}
	record.Token = token
	record.Enabled = enabled == 1
	record.LastCheckedAt = parseOptionalTime(lastCheckedRaw)
	record.CreatedAt = parseOptionalTime(createdRaw)
	record.UpdatedAt = parseOptionalTime(updatedRaw)
	record.LastStatus = normalizeAccountStatus(record.LastStatus)
	return record, nil
}

func normalizeAccountInput(input AccountInput) (AccountRecord, error) {
	record := AccountRecord{
		Label:    strings.TrimSpace(input.Label),
		Token:    strings.TrimSpace(input.Token),
		Enabled:  input.Enabled,
		Priority: input.Priority,
		Weight:   input.Weight,
	}
	if record.Priority == 0 {
		record.Priority = 100
	}
	if record.Weight == 0 {
		record.Weight = 1
	}
	record.TokenPreview = maskToken(record.Token)
	if err := validateAccountRecord(record); err != nil {
		return AccountRecord{}, err
	}
	return record, nil
}

func validateAccountRecord(record AccountRecord) error {
	switch {
	case strings.TrimSpace(record.Label) == "":
		return errors.New("账号标签不能为空")
	case strings.TrimSpace(record.Token) == "":
		return errors.New("token 不能为空")
	case record.Priority < 0:
		return errors.New("优先级不能小于 0")
	case record.Weight <= 0:
		return errors.New("权重必须大于 0")
	}
	return nil
}

func normalizeAccountStatus(status string) string {
	switch strings.TrimSpace(status) {
	case accountStatusHealthy:
		return accountStatusHealthy
	case accountStatusError:
		return accountStatusError
	case accountStatusInvalid:
		return accountStatusInvalid
	default:
		return accountStatusUnknown
	}
}

func parseOptionalTime(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

func formatOptionalTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func newAccountID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("acc-%d", time.Now().UnixNano())
	}
	return "acc-" + hex.EncodeToString(buf)
}

func maskToken(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	if len(token) <= 8 {
		return strings.Repeat("*", len(token))
	}
	return token[:4] + "..." + token[len(token)-4:]
}
