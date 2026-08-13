package blacklist

import (
	"testing"
	"time"
)

func TestBlacklistAddContains(t *testing.T) {
	b := New()
	defer b.Close()

	if b.Contains("1.2.3.4") {
		t.Error("IP should not be in blacklist initially")
	}

	if !b.Add("1.2.3.4") {
		t.Error("Add should return true for new IP")
	}

	if !b.Contains("1.2.3.4") {
		t.Error("IP should be in blacklist after Add")
	}

	// Повторное добавление того же IP должно вернуть false.
	if b.Add("1.2.3.4") {
		t.Error("Add should return false for already blacklisted IP")
	}
}

func TestBlacklistExpiration(t *testing.T) {
	ttl := 50 * time.Millisecond
	b := NewWithTTL(ttl)
	defer b.Close()

	b.Add("1.2.3.4")
	if !b.Contains("1.2.3.4") {
		t.Error("IP should be in blacklist immediately")
	}

	time.Sleep(ttl + 20*time.Millisecond)

	if b.Contains("1.2.3.4") {
		t.Error("IP should be expired after TTL")
	}
}

func TestBlacklistRemove(t *testing.T) {
	b := New()
	defer b.Close()

	b.Add("1.2.3.4")
	if !b.Contains("1.2.3.4") {
		t.Error("IP should be in blacklist")
	}

	b.Remove("1.2.3.4")
	if b.Contains("1.2.3.4") {
		t.Error("IP should be removed")
	}
}

func TestBlacklistClear(t *testing.T) {
	b := New()
	defer b.Close()

	b.Add("1.2.3.4")
	b.Add("5.6.7.8")

	if b.Len() != 2 {
		t.Errorf("Len = %d, want 2", b.Len())
	}

	b.Clear()
	if b.Len() != 0 {
		t.Errorf("Len after Clear = %d, want 0", b.Len())
	}
}

func TestBlacklistConcurrent(t *testing.T) {
	b := New()
	defer b.Close()

	done := make(chan bool)
	for i := range 10 {
		go func(idx int) {
			ip := "192.168.1." + string(rune('0'+idx%10))
			for j := 0; j < 100; j++ {
				b.Contains(ip)
				b.Add(ip)
				b.Remove(ip)
			}
			done <- true
		}(i)
	}

	for range 10 {
		<-done
	}
}
