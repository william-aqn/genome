// Package dashboard provides a real-time console UI for the Chameleon client.
package dashboard

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Stats tracks tunnel statistics.
type Stats struct {
	BytesSent      atomic.Int64
	BytesRecv      atomic.Int64
	OpenStreams     atomic.Int32
	TotalStreams    atomic.Int64
	PacketsSent    atomic.Int64
	PacketsRecv    atomic.Int64
	PacketsDropped atomic.Int64
}

type snapshot struct {
	sent, recv int64
	at         time.Time
}

const maxLogLines = 12

// Dashboard renders live stats in the terminal.
type Dashboard struct {
	stats      *Stats
	socksAddr  string
	socksUser  string
	socksPass  string
	serverAddr string
	startTime  time.Time

	prev     snapshot
	mu       sync.Mutex
	done     chan struct{}
	requests []string // stream open/close events
	logs     []string // debug/system logs
}

// New creates a dashboard.
func New(stats *Stats, socksAddr, socksUser, socksPass, serverAddr string) *Dashboard {
	now := time.Now()
	return &Dashboard{
		stats:      stats,
		socksAddr:  socksAddr,
		socksUser:  socksUser,
		socksPass:  socksPass,
		serverAddr: serverAddr,
		startTime:  now,
		prev:       snapshot{at: now},
		done:       make(chan struct{}),
	}
}

// Run starts the dashboard refresh loop.
func (d *Dashboard) Run() {
	d.hideCursor()
	d.clearScreen()
	d.render()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-d.done:
			d.showCursor()
			return
		case <-ticker.C:
			d.render()
		}
	}
}

// Stop stops the dashboard.
func (d *Dashboard) Stop() {
	select {
	case <-d.done:
	default:
		close(d.done)
	}
	d.moveTo(30, 1)
	d.showCursor()
	fmt.Println()
}

// LogRequest adds a message to the requests pane.
func (d *Dashboard) LogRequest(msg string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	ts := time.Now().Format("15:04:05")
	d.requests = append(d.requests, ts+" "+msg)
	if len(d.requests) > maxLogLines {
		d.requests = d.requests[len(d.requests)-maxLogLines:]
	}
}

// Log adds a message to the system log pane.
func (d *Dashboard) Log(msg string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	ts := time.Now().Format("15:04:05")
	d.logs = append(d.logs, ts+" "+msg)
	if len(d.logs) > maxLogLines {
		d.logs = d.logs[len(d.logs)-maxLogLines:]
	}
}

func (d *Dashboard) render() {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	sent := d.stats.BytesSent.Load()
	recv := d.stats.BytesRecv.Load()
	dt := now.Sub(d.prev.at).Seconds()

	var sendRate, recvRate float64
	if dt > 0.1 {
		sendRate = float64(sent-d.prev.sent) / dt
		recvRate = float64(recv-d.prev.recv) / dt
		d.prev = snapshot{sent: sent, recv: recv, at: now}
	}

	uptime := now.Sub(d.startTime)
	streams := d.stats.OpenStreams.Load()
	totalStreams := d.stats.TotalStreams.Load()
	pktSent := d.stats.PacketsSent.Load()
	pktRecv := d.stats.PacketsRecv.Load()
	pktDrop := d.stats.PacketsDropped.Load()

	row := 1

	// === Header ===
	d.at(row, 1, "\033[1m%s\033[0m\033[K", strings.Repeat("=", 72))
	row++
	d.at(row, 1, "\033[1m%s\033[0m\033[K", center(72, "CHAMELEON"))
	row++
	d.at(row, 1, "\033[1m%s\033[0m\033[K", strings.Repeat("=", 72))
	row++

	// === Stats ===
	d.at(row, 1, " %-11s %s\033[K", "Server:", d.serverAddr)
	row++
	d.at(row, 1, " %-11s %s\033[K", "SOCKS5:", d.socksAddr)
	row++
	d.at(row, 1, " %-11s %s  /  %s\033[K", "Auth:", d.socksUser, d.socksPass)
	row++
	d.at(row, 1, " %-11s \033[32m● CONNECTED\033[0m   Uptime: %s   %s\033[K",
		"Status:", formatDuration(uptime), now.Format("2006-01-02 15:04:05"))
	row++
	d.at(row, 1, " %-11s %d active / %d total\033[K", "Streams:", streams, totalStreams)
	row++
	d.at(row, 1, " %-11s ▲ %s (%s/s)   ▼ %s (%s/s)\033[K",
		"Traffic:",
		formatBytes(sent), formatBytes(int64(sendRate)),
		formatBytes(recv), formatBytes(int64(recvRate)))
	row++
	d.at(row, 1, " %-11s %d sent / %d recv / %d dropped\033[K",
		"Packets:", pktSent, pktRecv, pktDrop)
	row++

	// === Split: Requests | Logs ===
	leftW := 35
	rightW := 35
	sep := " | "

	d.at(row, 1, "%s\033[K", strings.Repeat("-", 72))
	row++
	d.at(row, 1, " %-*s%s%-*s\033[K", leftW, "Requests", sep, rightW, "Logs")
	row++
	d.at(row, 1, "%s\033[K", strings.Repeat("-", 72))
	row++

	for i := 0; i < maxLogLines; i++ {
		left := ""
		if i < len(d.requests) {
			left = d.requests[i]
		}
		right := ""
		if i < len(d.logs) {
			right = d.logs[i]
		}
		if len(left) > leftW {
			left = left[:leftW]
		}
		if len(right) > rightW {
			right = right[:rightW]
		}
		d.at(row, 1, " %-*s%s%-*s\033[K", leftW, left, sep, rightW, right)
		row++
	}

	d.at(row, 1, "%s\033[K", strings.Repeat("=", 72))
	row++
	d.at(row, 1, "%s\033[K", center(72, "Ctrl+C to stop"))
}

func (d *Dashboard) at(row, col int, format string, a ...any) {
	fmt.Fprintf(os.Stdout, "\033[%d;%dH", row, col)
	fmt.Fprintf(os.Stdout, format, a...)
}

func (d *Dashboard) moveTo(row, col int) {
	fmt.Fprintf(os.Stdout, "\033[%d;%dH", row, col)
}

func (d *Dashboard) clearScreen() {
	fmt.Fprint(os.Stdout, "\033[2J")
}

func (d *Dashboard) hideCursor() {
	fmt.Fprint(os.Stdout, "\033[?25l")
}

func (d *Dashboard) showCursor() {
	fmt.Fprint(os.Stdout, "\033[?25h")
}

func center(w int, text string) string {
	pad := (w - len(text)) / 2
	if pad < 0 {
		pad = 0
	}
	return strings.Repeat(" ", pad) + text
}

func formatBytes(b int64) string {
	switch {
	case b >= 1024*1024*1024:
		return fmt.Sprintf("%.1f GB", float64(b)/(1024*1024*1024))
	case b >= 1024*1024:
		return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
	case b >= 1024:
		return fmt.Sprintf("%.1f KB", float64(b)/1024)
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func formatDuration(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}
