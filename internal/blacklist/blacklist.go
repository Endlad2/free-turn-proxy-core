// Package blacklist реализует временный чёрный список IP-адресов TURN-серверов.
// Используется для того, чтобы не пытаться подключаться к недоступным серверам
// в течение определённого времени.
package blacklist

import (
	"sync"
	"time"
)

const (
	// DefaultTTL - время жизни записи в чёрном списке (5 минут).
	DefaultTTL = 5 * time.Minute

	// DefaultCleanupInterval - интервал очистки просроченных записей.
	DefaultCleanupInterval = 30 * time.Second
)

// Entry хранит время истечения записи.
type Entry struct {
	ExpiresAt time.Time
}

// Blacklist управляет временным чёрным списком IP-адресов.
type Blacklist struct {
	mu        sync.RWMutex
	entries   map[string]Entry
	ttl       time.Duration
	cleanupCh chan struct{}
	doneCh    chan struct{}
}

// New создаёт новый чёрный список с TTL по умолчанию.
func New() *Blacklist {
	return NewWithTTL(DefaultTTL)
}

// NewWithTTL создаёт чёрный список с указанным TTL.
func NewWithTTL(ttl time.Duration) *Blacklist {
	b := &Blacklist{
		entries:   make(map[string]Entry),
		ttl:       ttl,
		cleanupCh: make(chan struct{}, 1),
		doneCh:    make(chan struct{}),
	}
	go b.cleanupLoop()
	return b
}

// Add добавляет IP-адрес в чёрный список на TTL.
// Возвращает true, если IP был добавлен (не был в списке или срок истёк).
func (b *Blacklist) Add(ip string) bool {
	if ip == "" {
		return false
	}

	expiresAt := time.Now().Add(b.ttl)

	b.mu.Lock()
	defer b.mu.Unlock()

	// Проверяем, есть ли уже запись и не истекла ли она.
	if entry, exists := b.entries[ip]; exists && entry.ExpiresAt.After(time.Now()) {
		return false
	}

	b.entries[ip] = Entry{ExpiresAt: expiresAt}

	// Сигнализируем о необходимости очистки.
	select {
	case b.cleanupCh <- struct{}{}:
	default:
	}

	return true
}

// Contains проверяет, находится ли IP-адрес в чёрном списке.
func (b *Blacklist) Contains(ip string) bool {
	if ip == "" {
		return false
	}

	b.mu.RLock()
	entry, exists := b.entries[ip]
	b.mu.RUnlock()

	if !exists {
		return false
	}

	// Если запись истекла, удаляем её (очистка произойдёт при следующем проходе).
	if entry.ExpiresAt.Before(time.Now()) {
		b.mu.Lock()
		if e, stillExists := b.entries[ip]; stillExists && e.ExpiresAt.Before(time.Now()) {
			delete(b.entries, ip)
		}
		b.mu.Unlock()
		return false
	}

	return true
}

// Remove удаляет IP-адрес из чёрного списка.
func (b *Blacklist) Remove(ip string) {
	if ip == "" {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.entries, ip)
}

// Clear очищает весь чёрный список.
func (b *Blacklist) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries = make(map[string]Entry)
}

// Len возвращает количество IP-адресов в чёрном списке.
func (b *Blacklist) Len() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.entries)
}

// Close останавливает фоновую очистку.
func (b *Blacklist) Close() {
	close(b.doneCh)
}

// cleanupLoop удаляет просроченные записи.
func (b *Blacklist) cleanupLoop() {
	ticker := time.NewTicker(DefaultCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-b.doneCh:
			return
		case <-b.cleanupCh:
			b.cleanup()
		case <-ticker.C:
			b.cleanup()
		}
	}
}

// cleanup удаляет все просроченные записи.
func (b *Blacklist) cleanup() {
	now := time.Now()

	b.mu.Lock()
	defer b.mu.Unlock()

	for ip, entry := range b.entries {
		if entry.ExpiresAt.Before(now) {
			delete(b.entries, ip)
		}
	}
}
