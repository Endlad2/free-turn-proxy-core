package captcha

// Временная трассировка: полный дамп запросов и ответов captcha в один файл для
// ручного разбора. Включается FREETURN_CAPTCHA_TRACE=<путь>.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
)

var (
	traceMu  sync.Mutex
	traceSeq int
)

func traceValue(v string, limit int) string {
	if len(v) <= limit {
		return v
	}
	return fmt.Sprintf("%s…%s  [len=%d]", v[:limit/2], v[len(v)-limit/4:], len(v))
}

// traceHeaders отдаёт заголовки в том порядке, в каком их отправит fhttp.
func traceHeaders(h fhttp.Header) []string {
	order, _ := h[fhttp.HeaderOrderKey]
	seen := map[string]bool{}
	out := make([]string, 0, len(h))
	for _, name := range order {
		for key, values := range h {
			if strings.EqualFold(key, name) && !seen[key] {
				seen[key] = true
				out = append(out, fmt.Sprintf("%-27s %s", key+":", strings.Join(values, ", ")))
			}
		}
	}
	rest := make([]string, 0, len(h))
	for key, values := range h {
		if seen[key] || key == fhttp.HeaderOrderKey || key == fhttp.PHeaderOrderKey {
			continue
		}
		rest = append(rest, fmt.Sprintf("%-27s %s   <- вне списка порядка", key+":", strings.Join(values, ", ")))
	}
	sort.Strings(rest)
	return append(out, rest...)
}

func traceBody(body []byte) string {
	var pretty bytes.Buffer
	if json.Indent(&pretty, body, "", "  ") == nil {
		return traceValue(pretty.String(), 4000)
	}
	return traceValue(string(body), 2000)
}

func traceExchange(
	req *fhttp.Request,
	form [][2]string,
	resp *fhttp.Response,
	body []byte,
	elapsed time.Duration,
) {
	path := os.Getenv("FREETURN_CAPTCHA_TRACE")
	if path == "" {
		return
	}

	traceMu.Lock()
	defer traceMu.Unlock()
	traceSeq++

	var b strings.Builder
	fmt.Fprintf(&b, "\n## %d. %s %s\n\n", traceSeq, req.Method, req.URL.String())
	fmt.Fprintf(&b, "### Заголовки запроса (в порядке отправки)\n\n```\n:method %s\n:authority %s\n:scheme %s\n:path %s\n%s\n```\n\n",
		req.Method, req.URL.Host, req.URL.Scheme, req.URL.RequestURI(), strings.Join(traceHeaders(req.Header), "\n"))

	if len(form) > 0 {
		fmt.Fprintf(&b, "### Тело формы\n\n| поле | длина | значение |\n| --- | --- | --- |\n")
		for _, kv := range form {
			fmt.Fprintf(&b, "| `%s` | %d | `%s` |\n", kv[0], len(kv[1]), traceValue(kv[1], 200))
		}
		b.WriteString("\n")
	}

	if resp != nil {
		fmt.Fprintf(&b, "### Ответ %s за %s\n\n```\n", resp.Status, elapsed.Truncate(time.Millisecond))
		names := make([]string, 0, len(resp.Header))
		for key := range resp.Header {
			names = append(names, key)
		}
		sort.Strings(names)
		for _, key := range names {
			fmt.Fprintf(&b, "%-27s %s\n", key+":", traceValue(strings.Join(resp.Header[key], ", "), 300))
		}
		fmt.Fprintf(&b, "```\n\n```\n%s\n```\n", traceBody(body))
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		Log.Warnf("[Captcha][TRACE] open: %v", err)
		return
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(b.String()); err != nil {
		Log.Warnf("[Captcha][TRACE] write: %v", err)
	}
}
