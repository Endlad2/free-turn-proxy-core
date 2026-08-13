package routemgr

import (
	"net"
	"sync"

	"github.com/samosvalishe/free-turn-proxy/internal/blacklist"
	"github.com/samosvalishe/free-turn-proxy/internal/logx"
)

// Manager управляет маршрутами к TURN-серверам и ведёт чёрный список недоступных IP.
type Manager struct {
	gateway   string
	mu        sync.Mutex
	added     map[string]struct{}
	log       logx.Logger
	blacklist *blacklist.Blacklist
}

// New создаёт новый менеджер маршрутов.
func New(log logx.Logger) (*Manager, error) {
	gw, err := discoverGateway()
	if err != nil {
		return nil, err
	}
	if gw == "" {
		return nil, nil // unsupported platform
	}
	return &Manager{
		gateway:   gw,
		added:     make(map[string]struct{}),
		log:       logx.OrNop(log),
		blacklist: blacklist.New(),
	}, nil
}

// Gateway возвращает IP шлюза по умолчанию.
func (m *Manager) Gateway() string {
	if m == nil {
		return ""
	}
	return m.gateway
}

// IsBlacklisted проверяет, находится ли IP в чёрном списке.
func (m *Manager) IsBlacklisted(ip net.IP) bool {
	if m == nil {
		return false
	}
	return m.blacklist.Contains(ip.String())
}

// EnsureRouteToTURN добавляет маршрут к TURN-серверу через шлюз по умолчанию.
// При ошибке добавления маршрута IP вносится в чёрный список на 5 минут.
func (m *Manager) EnsureRouteToTURN(ip net.IP) {
	if m == nil {
		return
	}
	v4 := ip.To4()
	if v4 == nil {
		return // IPv6 not supported
	}
	key := v4.String()

	// Если IP в чёрном списке — пропускаем.
	if m.blacklist.Contains(key) {
		m.log.Debugf("Skipping route to %s: IP is blacklisted", key)
		return
	}

	m.mu.Lock()
	if _, ok := m.added[key]; ok {
		m.mu.Unlock()
		return
	}
	m.added[key] = struct{}{}
	m.mu.Unlock()

	m.log.Infof("Ensuring route to %s/32 via %s", key, m.gateway)
	if err := addRoute(key, m.gateway); err != nil {
		m.log.Warnf("failed to add route to %s: %v", key, err)

		// Вносим IP в чёрный список на 5 минут.
		m.blacklist.Add(key)
		m.log.Infof("IP %s added to blacklist for 5 minutes", key)

		m.mu.Lock()
		delete(m.added, key)
		m.mu.Unlock()
	}
}

// Close закрывает менеджер и удаляет все добавленные маршруты.
func (m *Manager) Close() error {
	if m == nil {
		return nil
	}
	defer m.blacklist.Close()

	m.mu.Lock()
	defer m.mu.Unlock()
	var firstErr error
	for ip := range m.added {
		m.log.Infof("Removing route to %s/32", ip)
		if err := delRoute(ip); err != nil {
			m.log.Warnf("failed to remove route to %s: %v", ip, err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	m.added = nil
	return firstErr
}

// Callback возвращает функцию для использования в udprelay/tcpfwd.
func (m *Manager) Callback() func(net.IP) {
	return m.EnsureRouteToTURN
}

// Blacklist возвращает чёрный список (для отладки).
func (m *Manager) Blacklist() *blacklist.Blacklist {
	if m == nil {
		return nil
	}
	return m.blacklist
}
