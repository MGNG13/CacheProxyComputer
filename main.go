package main
import (
	"bufio"
	"bytes"
	"compress/gzip"
	"container/list"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"github.com/elazarl/goproxy"
)
// ==================== CONFIGURACIÓN ====================
const (
	cacheMaxRAM         = 4 * 1024 * 1024 * 1024 // 4 GB
	maxEntrySize        = 200 * 1024 * 1024      // 200 MB por entrada
	defaultProxyPort    = ":8888"
	defaultAdminPort    = "127.0.0.1:8889"
	rulesReloadInterval = 30 * time.Second
	eventBacklogSize    = 1000
	maxRequestBodySize  = 450 * 1024 * 1024 // 450MB
)
// ==================== MODELOS ====================
type CacheEntry struct {
	key         string
	data        []byte
	contentType string
	size        int64
	etag        string
	hits        atomic.Uint64
	createdAt   time.Time
}
type CacheStats struct {
	Hits        uint64 `json:"hits"`
	Misses      uint64 `json:"misses"`
	Evictions   uint64 `json:"evictions"`
	CurrentSize int64  `json:"current_size_bytes"`
	MaxSize     int64  `json:"max_size_bytes"`
	Entries     int    `json:"entries"`
}
type Rules struct {
	BypassDomains         []string `json:"bypass_domains"`
	BlockDomains          []string `json:"block_domains"`
	BlockKeywords         []string `json:"block_keywords"`
	CacheableContentTypes []string `json:"cacheable_content_types"`
	CacheAllHosts         []string `json:"cache_all_hosts"`
}
type RequestEvent struct {
	Time   string `json:"time"`
	Method string `json:"method"`
	URL    string `json:"url"`
	Host   string `json:"host"`
	Action string `json:"action"`
}
type ProxyStats struct {
	TotalRequests     atomic.Uint64 `json:"total_requests"`
	BlockedRequests   atomic.Uint64 `json:"blocked_requests"`
	CacheHits         atomic.Uint64 `json:"cache_hits"`
	CacheMisses       atomic.Uint64 `json:"cache_misses"`
	ActiveConnections atomic.Int64  `json:"active_connections"`
	Uptime            time.Time     `json:"uptime"`
}
// ==================== MEMORY CACHE (LRU) ====================
type MemoryCache struct {
	mu          sync.RWMutex
	maxSize     int64
	currentSize int64
	items       map[string]*list.Element
	lruList     *list.List
	stats       CacheStats
}
func NewMemoryCache(maxSize int64) *MemoryCache {
	return &MemoryCache{
		maxSize: maxSize,
		items:   make(map[string]*list.Element),
		lruList: list.New(),
		stats:   CacheStats{MaxSize: maxSize},
	}
}
func (c *MemoryCache) Get(key string) ([]byte, string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if elem, ok := c.items[key]; ok {
		c.lruList.MoveToFront(elem)
		entry := elem.Value.(*CacheEntry)
		entry.hits.Add(1)
		c.stats.Hits++
		return entry.data, entry.contentType, true
	}
	c.stats.Misses++
	return nil, "", false
}
func (c *MemoryCache) Put(key, contentType string, body []byte, alreadyCompressed bool) {
	if int64(len(body)) > maxEntrySize {
		log.Printf("[cache] entrada demasiado grande (%d bytes), omitida", len(body))
		return
	}
	var data []byte
	if alreadyCompressed {
		data = body
	} else {
		var buf bytes.Buffer
		gz, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
		if err != nil {
			log.Printf("[cache] error creando gzip: %v", err)
			return
		}
		if _, err = gz.Write(body); err != nil {
			log.Printf("[cache] error al comprimir: %v", err)
			gz.Close()
			return
		}
		if err = gz.Close(); err != nil {
			log.Printf("[cache] error al cerrar gzip: %v", err)
			return
		}
		data = buf.Bytes()
	}
	entrySize := int64(len(data))
	etag := fmt.Sprintf(`"%s"`, hex.EncodeToString(sha256.New().Sum(data))[:16])
	c.mu.Lock()
	defer c.mu.Unlock()
	if entrySize > c.maxSize {
		log.Printf("[cache] entrada demasiado grande para el maximo de cache (%d > %d), omitida", entrySize, c.maxSize)
		return
	}
	// Reemplazar si existe
	if elem, ok := c.items[key]; ok {
		old := elem.Value.(*CacheEntry)
		c.currentSize -= old.size
		c.lruList.Remove(elem)
		delete(c.items, key)
	}
	if c.currentSize+entrySize > c.maxSize {
		removedEntries, removedBytes := c.purgeAllLocked()
		if removedEntries > 0 {
			c.stats.Evictions += uint64(removedEntries)
			log.Printf("[cache] cache purgada por limite de RAM: %d entradas, %d bytes", removedEntries, removedBytes)
		}
	}
	entry := &CacheEntry{
		key:         key,
		data:        data,
		contentType: contentType,
		size:        entrySize,
		etag:        etag,
		createdAt:   time.Now(),
	}
	elem := c.lruList.PushFront(entry)
	c.items[key] = elem
	c.currentSize += entrySize
}
func (c *MemoryCache) purgeAllLocked() (removedEntries int, removedBytes int64) {
	removedEntries = len(c.items)
	removedBytes = c.currentSize
	c.items = make(map[string]*list.Element)
	c.lruList.Init()
	c.currentSize = 0
	return removedEntries, removedBytes
}
func (c *MemoryCache) Stats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return CacheStats{
		Hits:        c.stats.Hits,
		Misses:      c.stats.Misses,
		Evictions:   c.stats.Evictions,
		CurrentSize: c.currentSize,
		MaxSize:     c.maxSize,
		Entries:     len(c.items),
	}
}
func (c *MemoryCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[string]*list.Element)
	c.lruList.Init()
	c.currentSize = 0
	c.stats = CacheStats{MaxSize: c.maxSize}
}
// ==================== EVENT HUB (SSE) ====================
type eventHub struct {
	mu       sync.RWMutex
	clients  map[chan string]struct{}
	backlog  []string
	capacity int
}
func newEventHub(capacity int) *eventHub {
	return &eventHub{
		clients:  make(map[chan string]struct{}),
		backlog:  make([]string, 0, capacity),
		capacity: capacity,
	}
}
func (h *eventHub) Publish(ev RequestEvent) {
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	msg := string(b)
	h.mu.Lock()
	if h.capacity > 0 {
		if len(h.backlog) >= h.capacity {
			h.backlog = append(h.backlog[1:], msg)
		} else {
			h.backlog = append(h.backlog, msg)
		}
	}
	for ch := range h.clients {
		select {
		case ch <- msg:
		default: // cliente lento, descartar
		}
	}
	h.mu.Unlock()
}
func (h *eventHub) Subscribe() (chan string, []string) {
	ch := make(chan string, 100)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	snapshot := make([]string, len(h.backlog))
	copy(snapshot, h.backlog)
	h.mu.Unlock()
	return ch, snapshot
}
func (h *eventHub) Unsubscribe(ch chan string) {
	h.mu.Lock()
	delete(h.clients, ch)
	h.mu.Unlock()
	close(ch)
}
// ==================== RULES MANAGER ====================
type RulesManager struct {
	configDir string
	current   atomic.Value
	mu        sync.RWMutex
}
func NewRulesManager(configDir string) *RulesManager {
	rm := &RulesManager{configDir: configDir}
	rm.current.Store(defaultRules())
	return rm
}
func (rm *RulesManager) Get() Rules {
	return rm.current.Load().(Rules)
}
func (rm *RulesManager) Reload() error {
	r, err := rm.loadFromFiles()
	if err != nil {
		return err
	}
	rm.current.Store(r)
	return nil
}
func (rm *RulesManager) loadFromFiles() (Rules, error) {
	r := defaultRules()
	type fileMapping struct {
		name      string
		dest      *[]string
		normalize func(string) string
	}
	mappings := []fileMapping{
		{"bypass_domains.txt", &r.BypassDomains, normalizeDomain},
		{"blocked_domains.txt", &r.BlockDomains, normalizeDomain},
		{"blocked_keywords.txt", &r.BlockKeywords, normalizeKeyword},
		{"cacheable_content_types.txt", &r.CacheableContentTypes, normalizeContentType},
		{"cached.txt", &r.CacheAllHosts, normalizeKeyword},
	}
	for _, m := range mappings {
		lines, err := readLines(filepath.Join(rm.configDir, m.name))
		if err != nil {
			if os.IsNotExist(err) {
				continue // archivo opcional
			}
			return Rules{}, fmt.Errorf("%s: %w", m.name, err)
		}
		*m.dest = normalizeList(lines, m.normalize)
	}
	return r, nil
}
func (rm *RulesManager) FilePath(name string) string {
	return filepath.Join(rm.configDir, name)
}
func defaultRules() Rules {
	return Rules{
		BypassDomains:         []string{},
		BlockDomains:          []string{},
		BlockKeywords:         []string{},
		CacheableContentTypes: []string{"text/", "application/json", "application/javascript", "application/xml"},
		CacheAllHosts:         []string{"cdn", "img", "ggpht.com", "googlevideo.com"},
	}
}
// ==================== UTILIDADES ====================
func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}
func normalizeList(in []string, normalize func(string) string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, v := range in {
		n := normalize(v)
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}
func normalizeDomain(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if h, _, err := net.SplitHostPort(v); err == nil {
		v = h
	}
	v = strings.TrimPrefix(v, "*.")
	v = strings.TrimLeft(v, ".")
	return strings.TrimSuffix(v, ".")
}
func normalizeKeyword(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}
func normalizeContentType(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}
func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.TrimSuffix(host, ".")
}
func corsOriginForRequest(req *http.Request) (string, bool) {
	origin := strings.TrimSpace(req.Header.Get("Origin"))
	if origin == "" {
		return "", false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return "", false
	}
	reqHost := req.URL.Host
	if reqHost == "" {
		reqHost = req.Host
	}
	if normalizeHost(u.Host) != normalizeHost(reqHost) {
		return "", false
	}
	return origin, true
}
func varyAppend(h http.Header, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	existing := h.Get("Vary")
	if existing == "" {
		h.Set("Vary", value)
		return
	}
	for _, part := range strings.Split(existing, ",") {
		if strings.EqualFold(strings.TrimSpace(part), value) {
			return
		}
	}
	h.Set("Vary", existing+", "+value)
}
func applyCORSHeaders(h http.Header, req *http.Request, origin string) {
	if origin == "" {
		return
	}
	if h.Get("Access-Control-Allow-Origin") == "" {
		h.Set("Access-Control-Allow-Origin", origin)
	}
	if h.Get("Access-Control-Allow-Credentials") == "" {
		h.Set("Access-Control-Allow-Credentials", "true")
	}
	if h.Get("Access-Control-Allow-Methods") == "" {
		h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
	}
	if h.Get("Access-Control-Allow-Headers") == "" {
		if acrh := strings.TrimSpace(req.Header.Get("Access-Control-Request-Headers")); acrh != "" {
			h.Set("Access-Control-Allow-Headers", acrh)
		} else {
			h.Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		}
	}
	if h.Get("Access-Control-Max-Age") == "" {
		h.Set("Access-Control-Max-Age", "600")
	}
	varyAppend(h, "Origin")
}
func shouldCacheAll(host string, rules Rules) bool {
	h := normalizeHost(host)
	for _, token := range rules.CacheAllHosts {
		token = strings.ToLower(strings.TrimSpace(token))
		if token == "" {
			continue
		}
		if strings.Contains(token, ".") {
			if h == token || strings.HasSuffix(h, "."+token) {
				return true
			}
			continue
		}
		if strings.Contains(h, token) {
			return true
		}
	}
	return false
}
func isLocalDestination(host string) bool {
	h := normalizeHost(host)
	h = strings.TrimPrefix(h, "[")
	h = strings.TrimSuffix(h, "]")
	if h == "localhost" || h == "localhost.localdomain" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}
func getCacheKey(urlStr string) string {
	hash := sha256.Sum256([]byte(urlStr))
	return hex.EncodeToString(hash[:])
}
func isCacheable(contentType string, rules Rules) bool {
	ct := strings.ToLower(contentType)
	for _, a := range rules.CacheableContentTypes {
		if strings.Contains(ct, a) {
			return true
		}
	}
	return false
}
func shouldBypassMitm(host string, rules Rules) bool {
	hostOnly := normalizeHost(host)
	for _, d := range rules.BypassDomains {
		if hostOnly == d || strings.HasSuffix(hostOnly, "."+d) {
			return true
		}
	}
	return false
}
func shouldBlockDomain(host string, rules Rules) bool {
	hostOnly := normalizeHost(host)
	for _, d := range rules.BlockDomains {
		if hostOnly == d || strings.HasSuffix(hostOnly, "."+d) {
			return true
		}
	}
	return false
}
func shouldBlockByKeyword(value string, rules Rules) bool {
	value = strings.ToLower(value)
	for _, kw := range rules.BlockKeywords {
		if kw != "" && strings.Contains(value, kw) {
			return true
		}
	}
	return false
}
func configDir() string {
	if wd, err := os.Getwd(); err == nil && wd != "" {
		return wd
	}
	if exe, err := os.Executable(); err == nil && exe != "" {
		return filepath.Dir(exe)
	}
	return "."
}
func blockedResponse(req *http.Request) *http.Response {
	body := "blocked"
	return &http.Response{
		StatusCode:    http.StatusForbidden,
		Status:        "403 Forbidden",
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}
// ==================== ADMIN SERVER ====================
type AdminServer struct {
	rm      *RulesManager
	cache   *MemoryCache
	stats   *ProxyStats
	events  *eventHub
	handler http.Handler
}
func NewAdminServer(rm *RulesManager, cache *MemoryCache, stats *ProxyStats, events *eventHub) *AdminServer {
	a := &AdminServer{rm: rm, cache: cache, stats: stats, events: events}
	mux := http.NewServeMux()
	// API routes
	mux.HandleFunc("/api/stats", a.cors(a.statsHandler))
	mux.HandleFunc("/api/cache/stats", a.cors(a.cacheStatsHandler))
	mux.HandleFunc("/api/cache/clear", a.cors(a.cacheClearHandler))
	mux.HandleFunc("/api/rules", a.cors(a.rulesHandler))
	mux.HandleFunc("/api/file/", a.cors(a.fileHandler))
	mux.HandleFunc("/api/events", a.cors(a.eventsHandler))
	mux.HandleFunc("/api/health", a.cors(a.healthHandler))
	// Static
	mux.HandleFunc("/", a.indexHandler)
	a.handler = securityHeaders(mux)
	return a
}
func (a *AdminServer) cors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
		next.ServeHTTP(w, r)
	})
}
func (a *AdminServer) statsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"total_requests":     a.stats.TotalRequests.Load(),
		"blocked_requests":   a.stats.BlockedRequests.Load(),
		"cache_hits":         a.stats.CacheHits.Load(),
		"cache_misses":       a.stats.CacheMisses.Load(),
		"active_connections": a.stats.ActiveConnections.Load(),
		"uptime":             time.Since(a.stats.Uptime).Seconds(),
		"go_version":         runtime.Version(),
		"goroutines":         runtime.NumGoroutine(),
	})
}
func (a *AdminServer) cacheStatsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(a.cache.Stats())
}
func (a *AdminServer) cacheClearHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.cache.Clear()
	w.WriteHeader(http.StatusNoContent)
}
func (a *AdminServer) rulesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(a.rm.Get())
}
func (a *AdminServer) fileHandler(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(r.URL.Path, "/api/file/")
	name, ok := fileNameForKey(key)
	if !ok {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	path := a.rm.FilePath(name)
	switch r.Method {
	case http.MethodGet:
		b, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				w.WriteHeader(http.StatusOK)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(b)
	case http.MethodPut:
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBodySize))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := os.WriteFile(path, body, 0644); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := a.rm.Reload(); err != nil {
			log.Printf("[admin] error recargando reglas: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
func (a *AdminServer) eventsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	ch, snapshot := a.events.Subscribe()
	defer a.events.Unsubscribe(ch)
	for _, msg := range snapshot {
		fmt.Fprintf(w, "data: %s\n\n", msg)
	}
	flusher.Flush()
	ctx := r.Context()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		case <-ticker.C:
			fmt.Fprint(w, ":ping\n\n")
			flusher.Flush()
		}
	}
}
func (a *AdminServer) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
func (a *AdminServer) indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(adminHTML))
}
func (a *AdminServer) Start(addr string) error {
	srv := &http.Server{
		Addr:         addr,
		Handler:      a.handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 0, // SSE requiere write infinito
		IdleTimeout:  120 * time.Second,
	}
	log.Printf("[admin] panel en http://%s", addr)
	return srv.ListenAndServe()
}
func fileNameForKey(key string) (string, bool) {
	switch key {
	case "bypass_domains":
		return "bypass_domains.txt", true
	case "blocked_domains":
		return "blocked_domains.txt", true
	case "blocked_keywords":
		return "blocked_keywords.txt", true
	case "cacheable_content_types":
		return "cacheable_content_types.txt", true
	case "cached":
		return "cached.txt", true
	default:
		return "", false
	}
}
// ==================== PROXY ====================
type ProxyServer struct {
	rm     *RulesManager
	cache  *MemoryCache
	stats  *ProxyStats
	events *eventHub
	proxy  *goproxy.ProxyHttpServer
}
type cacheCtx struct {
	cacheKey string
	cacheAll bool
}
func NewProxyServer(rm *RulesManager, cache *MemoryCache, stats *ProxyStats, events *eventHub) *ProxyServer {
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		log.Fatalf("[proxy] error cargando certificados: %v", err)
	}
	goproxy.GoproxyCa = cert
	p := goproxy.NewProxyHttpServer()
	p.Verbose = false // Reducir ruido de logs
	p.Tr = &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
	}
	s := &ProxyServer{rm: rm, cache: cache, stats: stats, events: events, proxy: p}
	s.setupHandlers()
	return s
}
func (s *ProxyServer) setupHandlers() {
	// CONNECT handler (MITM decisions)
	s.proxy.OnRequest().HandleConnect(
		goproxy.FuncHttpsHandler(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
			s.stats.ActiveConnections.Add(1)
			defer s.stats.ActiveConnections.Add(-1)
			hostLower := strings.ToLower(host)
			hostOnly := normalizeHost(hostLower)
			rules := s.rm.Get()
			if isLocalDestination(hostOnly) {
				s.publishEvent("CONNECT", host, hostOnly, "bypass_local")
				return goproxy.OkConnect, host
			}
			if shouldBlockByKeyword(hostOnly, rules) {
				s.publishEvent("CONNECT", host, hostOnly, "blocked_keyword")
				log.Printf("[proxy] BLOCK CONNECT (keyword): %s", host)
				return goproxy.RejectConnect, host
			}
			if shouldBlockDomain(hostLower, rules) {
				s.publishEvent("CONNECT", host, hostOnly, "blocked_domain")
				log.Printf("[proxy] BLOCK CONNECT (domain): %s", host)
				return goproxy.RejectConnect, host
			}
			if shouldBypassMitm(hostLower, rules) {
				s.publishEvent("CONNECT", host, hostOnly, "bypass_mitm")
				return goproxy.OkConnect, host
			}
			if strings.Contains(strings.ToLower(ctx.Req.Header.Get("Upgrade")), "websocket") {
				s.publishEvent("CONNECT", host, hostOnly, "upgrade_websocket")
				return goproxy.OkConnect, host
			}
			if strings.Contains(hostLower, "microsoft.com") {
				s.publishEvent("CONNECT", host, hostOnly, "bypass_microsoft")
				return goproxy.OkConnect, host
			}
			s.publishEvent("CONNECT", host, hostOnly, "mitm")
			return goproxy.MitmConnect, host
		}),
	)
	// Response interceptor (caching)
	s.proxy.OnResponse().DoFunc(
		func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
			if resp == nil || resp.Body == nil {
				return resp
			}
			origin, corsOK := corsOriginForRequest(ctx.Req)
			reqHost := strings.ToLower(ctx.Req.URL.Host)
			if reqHost == "" {
				reqHost = strings.ToLower(ctx.Req.Host)
			}
			hostOnly := normalizeHost(reqHost)
			cacheAll := shouldCacheAll(hostOnly, s.rm.Get())
			if isLocalDestination(reqHost) {
				if corsOK {
					applyCORSHeaders(resp.Header, ctx.Req, origin)
				}
				return resp
			}
			if !cacheAll && resp.Header.Get("Access-Control-Allow-Origin") != "" {
				if corsOK {
					applyCORSHeaders(resp.Header, ctx.Req, origin)
				}
				return resp
			}
			if !cacheAll {
				if ctx.Req.Method != http.MethodGet {
					if corsOK {
						applyCORSHeaders(resp.Header, ctx.Req, origin)
					}
					return resp
				}
			}
			if strings.Contains(strings.ToLower(resp.Header.Get("Upgrade")), "websocket") {
				if corsOK {
					applyCORSHeaders(resp.Header, ctx.Req, origin)
				}
				return resp
			}
			rules := s.rm.Get()
			contentType := resp.Header.Get("Content-Type")
			urlStr := ctx.Req.URL.String()
			key := ""
			if v, ok := ctx.UserData.(*cacheCtx); ok && v != nil && v.cacheKey != "" {
				key = v.cacheKey
			} else {
				if cacheAll {
					key = getCacheKey(ctx.Req.Method + " " + urlStr)
				} else {
					key = getCacheKey(urlStr)
				}
			}
			bodyBytes, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			if readErr != nil {
				log.Printf("[proxy] error leyendo body: %v", readErr)
				return resp
			}
			if cacheAll {
				alreadyCompressed := strings.Contains(resp.Header.Get("Content-Encoding"), "gzip")
				s.publishEvent(ctx.Req.Method, urlStr, hostOnly, "cache_store")
				go s.cache.Put(key, contentType, bodyBytes, alreadyCompressed)
				if corsOK {
					applyCORSHeaders(resp.Header, ctx.Req, origin)
				}
				return resp
			}
			if isCacheable(contentType, rules) && resp.StatusCode == http.StatusOK {
				cacheControl := strings.ToLower(resp.Header.Get("Cache-Control"))
				if !strings.Contains(cacheControl, "no-store") && !strings.Contains(cacheControl, "no-cache") {
					alreadyCompressed := strings.Contains(resp.Header.Get("Content-Encoding"), "gzip")
					go s.cache.Put(key, contentType, bodyBytes, alreadyCompressed)
				}
			}
			if corsOK {
				applyCORSHeaders(resp.Header, ctx.Req, origin)
			}
			return resp
		},
	)
	// Request interceptor (cache serve + blocking)
	s.proxy.OnRequest().DoFunc(
		func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			s.stats.TotalRequests.Add(1)
			origin, corsOK := corsOriginForRequest(req)
			hostLower := strings.ToLower(req.URL.Host)
			if hostLower == "" {
				hostLower = strings.ToLower(req.Host)
			}
			hostOnly := normalizeHost(hostLower)
			urlStr := req.URL.String()
			urlLower := strings.ToLower(urlStr)
			rules := s.rm.Get()
			if isLocalDestination(hostOnly) {
				s.publishEvent(req.Method, req.URL.String(), hostOnly, "bypass_local")
				return req, nil
			}
			// Block by keyword
			if shouldBlockByKeyword(urlLower, rules) || shouldBlockByKeyword(hostOnly, rules) {
				s.stats.BlockedRequests.Add(1)
				s.publishEvent(req.Method, req.URL.String(), hostOnly, "blocked_keyword")
				return req, blockedResponse(req)
			}
			// Block by domain
			if shouldBlockDomain(hostLower, rules) {
				s.stats.BlockedRequests.Add(1)
				s.publishEvent(req.Method, req.URL.String(), hostOnly, "blocked_domain")
				return req, blockedResponse(req)
			}
			if corsOK && req.Method == http.MethodOptions && strings.TrimSpace(req.Header.Get("Access-Control-Request-Method")) != "" {
				resp := &http.Response{
					StatusCode: http.StatusNoContent,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("")),
					Request:    req,
				}
				applyCORSHeaders(resp.Header, req, origin)
				resp.ContentLength = 0
				s.publishEvent(req.Method, urlStr, hostOnly, "cors_preflight")
				return req, resp
			}
			// Cache lookup
			cacheAll := shouldCacheAll(hostOnly, rules)
			key := ""
			if cacheAll {
				key = getCacheKey(req.Method + " " + urlStr)
			} else {
				key = getCacheKey(urlStr)
			}
			ctx.UserData = &cacheCtx{cacheKey: key, cacheAll: cacheAll}
			if !cacheAll && req.Method != http.MethodGet && req.Method != http.MethodHead {
				s.publishEvent(req.Method, urlStr, hostOnly, "request")
				return req, nil
			}
			if data, contentType, found := s.cache.Get(key); found {
				s.stats.CacheHits.Add(1)
				s.publishEvent(req.Method, urlStr, hostOnly, "cache_hit")
				log.Printf("[cache] HIT: %s", urlStr)
				acceptsGzip := strings.Contains(req.Header.Get("Accept-Encoding"), "gzip")
				var bodyReader io.ReadCloser
				var contentEncoding string
				if acceptsGzip {
					contentEncoding = "gzip"
					if req.Method != http.MethodHead {
						bodyReader = io.NopCloser(bytes.NewReader(data))
					} else {
						bodyReader = io.NopCloser(bytes.NewReader(nil))
					}
				} else {
					gzReader, err := gzip.NewReader(bytes.NewReader(data))
					if err != nil {
						log.Printf("[cache] error descomprimiendo: %v", err)
						return req, nil
					}
					decompressed, err := io.ReadAll(gzReader)
					gzReader.Close()
					if err != nil {
						log.Printf("[cache] error leyendo descompresión: %v", err)
						return req, nil
					}
					if req.Method != http.MethodHead {
						bodyReader = io.NopCloser(bytes.NewReader(decompressed))
					} else {
						bodyReader = io.NopCloser(bytes.NewReader(nil))
					}
				}
				resp := &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       bodyReader,
					Request:    req,
				}
				resp.Header.Set("Content-Type", contentType)
				resp.Header.Set("X-Cache", "HIT")
				if contentEncoding != "" {
					resp.Header.Set("Content-Encoding", contentEncoding)
				}
				if corsOK {
					applyCORSHeaders(resp.Header, req, origin)
				}
				if req.Method == http.MethodHead {
					resp.ContentLength = 0
				}
				return req, resp
			}
			s.stats.CacheMisses.Add(1)
			s.publishEvent(req.Method, urlStr, hostOnly, "request")
			return req, nil
		},
	)
}
func (s *ProxyServer) publishEvent(method, urlStr, host, action string) {
	s.events.Publish(RequestEvent{
		Time:   time.Now().Format(time.RFC3339),
		Method: method,
		URL:    urlStr,
		Host:   host,
		Action: action,
	})
}
func (s *ProxyServer) Start(addr string) error {
	log.Printf("[proxy] escuchando en %s", addr)
	return http.ListenAndServe(addr, s.proxy)
}
// ==================== MAIN ====================
func main() {
	rm := NewRulesManager(configDir())
	if err := rm.Reload(); err != nil {
		log.Printf("[init] error cargando reglas iniciales: %v", err)
	}
	cache := NewMemoryCache(cacheMaxRAM)
	stats := &ProxyStats{Uptime: time.Now()}
	events := newEventHub(eventBacklogSize)
	// Rules reloader
	go func() {
		ticker := time.NewTicker(rulesReloadInterval)
		defer ticker.Stop()
		for range ticker.C {
			if err := rm.Reload(); err != nil {
				log.Printf("[rules] error recargando: %v", err)
			}
		}
	}()
	// Admin server
	admin := NewAdminServer(rm, cache, stats, events)
	go func() {
		if err := admin.Start(defaultAdminPort); err != nil {
			log.Fatalf("[admin] error: %v", err)
		}
	}()
	// Proxy server
	proxy := NewProxyServer(rm, cache, stats, events)
	log.Fatal(proxy.Start(defaultProxyPort))
}
// ==================== HTML ADMIN ====================
const adminHTML = `<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Proxy Admin Dashboard</title>
  <style>
    :root {
      --bg: #0f172a;
      --card: #1e293b;
      --border: #334155;
      --text: #e2e8f0;
      --muted: #94a3b8;
      --accent: #3b82f6;
      --accent-hover: #2563eb;
      --danger: #ef4444;
      --success: #22c55e;
      --warning: #f59e0b;
      --font: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: var(--font);
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      min-height: 100vh;
    }
    header {
      background: var(--card);
      border-bottom: 1px solid var(--border);
      padding: 1rem 1.5rem;
      position: sticky;
      top: 0;
      z-index: 10;
    }
    header h1 { font-size: 1.25rem; font-weight: 600; }
    header .subtitle { color: var(--muted); font-size: 0.875rem; }
    .container { max-width: 1400px; margin: 0 auto; padding: 1.5rem; }
    .grid { display: grid; gap: 1rem; margin-bottom: 1.5rem; }
    .grid-4 { grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); }
    .grid-2 { grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 0.75rem;
      padding: 1.25rem;
    }
    .card h2 {
      font-size: 0.875rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--muted);
      margin-bottom: 0.75rem;
    }
    .stat-value {
      font-size: 1.875rem;
      font-weight: 700;
      font-family: var(--mono);
    }
    .stat-label { color: var(--muted); font-size: 0.875rem; }
    .badge {
      display: inline-flex;
      align-items: center;
      padding: 0.125rem 0.5rem;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 600;
    }
    .badge-success { background: rgba(34,197,94,0.15); color: var(--success); }
    .badge-warning { background: rgba(245,158,11,0.15); color: var(--warning); }
    .badge-danger { background: rgba(239,68,68,0.15); color: var(--danger); }
    .toolbar {
      display: flex;
      gap: 0.75rem;
      align-items: center;
      margin-bottom: 1rem;
      flex-wrap: wrap;
    }
    select, button, input {
      background: var(--bg);
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 0.5rem;
      padding: 0.5rem 0.75rem;
      font-family: inherit;
      font-size: 0.875rem;
      cursor: pointer;
    }
    button {
      background: var(--accent);
      border-color: var(--accent);
      font-weight: 500;
      transition: all 0.15s;
    }
    button:hover { background: var(--accent-hover); border-color: var(--accent-hover); }
    button.secondary {
      background: transparent;
      border-color: var(--border);
    }
    button.secondary:hover { background: var(--border); }
    button.danger {
      background: var(--danger);
      border-color: var(--danger);
    }
    textarea {
      width: 100%;
      height: 280px;
      background: var(--bg);
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 0.5rem;
      padding: 0.75rem;
      font-family: var(--mono);
      font-size: 0.8125rem;
      line-height: 1.5;
      resize: vertical;
    }
    textarea:focus, select:focus, button:focus {
      outline: 2px solid var(--accent);
      outline-offset: 2px;
    }
    .log-container {
      background: #020617;
      border: 1px solid var(--border);
      border-radius: 0.5rem;
      height: 400px;
      overflow: auto;
      padding: 0.75rem;
    }
    .log-line {
      font-family: var(--mono);
      font-size: 0.75rem;
      line-height: 1.6;
      padding: 0.125rem 0;
      border-bottom: 1px solid rgba(51,65,85,0.3);
      white-space: nowrap;
    }
    .log-time { color: #64748b; }
    .log-action { font-weight: 600; }
    .log-action.cache_hit { color: var(--success); }
    .log-action.cache_store { color: var(--accent); }
    .log-action.blocked_domain, .log-action.blocked_keyword { color: var(--danger); }
    .log-action.mitm { color: var(--warning); }
    .log-action.bypass_mitm { color: #a78bfa; }
    .log-url { color: #94a3b8; margin-left: 0.5rem; }
    .status-bar {
      display: flex;
      gap: 1rem;
      align-items: center;
      font-size: 0.75rem;
      color: var(--muted);
      margin-top: 0.5rem;
    }
    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--success);
      animation: pulse 2s infinite;
    }
    @keyframes pulse {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.5; }
    }
    .progress-bar {
      width: 100%;
      height: 8px;
      background: var(--bg);
      border-radius: 4px;
      overflow: hidden;
      margin-top: 0.5rem;
    }
    .progress-fill {
      height: 100%;
      background: var(--accent);
      border-radius: 4px;
      transition: width 0.3s ease;
    }
    @media (max-width: 768px) {
      .grid-2 { grid-template-columns: 1fr; }
      .grid-4 { grid-template-columns: repeat(2, 1fr); }
    }
  </style>
</head>
<body>
  <header>
    <h1>Proxy Admin Dashboard</h1>
    <div class="subtitle">MITM Proxy con cache LRU - Puerto proxy: 8888 - Admin: 8889</div>
  </header>
  <div class="container">
    <!-- Stats -->
    <div class="grid grid-4" id="stats-grid">
      <div class="card">
        <h2>Total Requests</h2>
        <div class="stat-value" id="stat-total">0</div>
        <div class="stat-label">desde el inicio</div>
      </div>
      <div class="card">
        <h2>Cache Hit Rate</h2>
        <div class="stat-value" id="stat-hitrate">0%</div>
        <div class="stat-label" id="stat-cache-detail">0 hits / 0 misses</div>
      </div>
      <div class="card">
        <h2>Bloqueados</h2>
        <div class="stat-value" id="stat-blocked">0</div>
        <div class="stat-label">requests denegados</div>
      </div>
      <div class="card">
        <h2>Uptime</h2>
        <div class="stat-value" id="stat-uptime">0s</div>
        <div class="stat-label" id="stat-goroutines">0 goroutines</div>
      </div>
    </div>
    <!-- Cache Stats -->
    <div class="grid grid-4" id="cache-stats-grid">
      <div class="card">
        <h2>Cache Entradas</h2>
        <div class="stat-value" id="cache-entries">0</div>
      </div>
      <div class="card">
        <h2>Cache Usado</h2>
        <div class="stat-value" id="cache-size">0 MB</div>
        <div class="progress-bar"><div class="progress-fill" id="cache-bar" style="width:0%"></div></div>
      </div>
      <div class="card">
        <h2>Cache Hits</h2>
        <div class="stat-value" id="cache-hits">0</div>
      </div>
      <div class="card">
        <h2>Evictions</h2>
        <div class="stat-value" id="cache-evictions">0</div>
      </div>
    </div>
    <div class="grid grid-2">
      <!-- Rules Editor -->
      <div class="card">
        <h2>Editor de Reglas</h2>
        <div class="toolbar">
          <select id="file">
            <option value="blocked_domains">blocked_domains.txt</option>
            <option value="bypass_domains">bypass_domains.txt</option>
            <option value="blocked_keywords">blocked_keywords.txt</option>
            <option value="cacheable_content_types">cacheable_content_types.txt</option>
            <option value="cached">cached.txt</option>
          </select>
          <button id="load">Cargar</button>
          <button id="save">Guardar</button>
          <button class="secondary" id="reload">Recargar Reglas</button>
        </div>
        <textarea id="editor" spellcheck="false" placeholder="# Una regla por linea&#10;# Lineas que empiezan con # son comentarios"></textarea>
        <div class="status-bar">
          <span class="status-dot"></span>
          <span id="conn-status">Conectado a eventos</span>
          <span id="last-save">-</span>
        </div>
      </div>
      <!-- Live Log -->
      <div class="card">
        <h2>Requests en Tiempo Real</h2>
        <div class="toolbar">
          <button class="secondary" id="clear-log">Limpiar</button>
          <button class="danger" id="clear-cache">Vaciar Cache</button>
          <span class="badge badge-success" id="log-count">0 lineas</span>
        </div>
        <div class="log-container" id="log"></div>
      </div>
    </div>
  </div>
<script>
const $ = id => document.getElementById(id);
const fmtNum = n => new Intl.NumberFormat('es-ES').format(n);
const fmtBytes = b => b > 1073741824 ? (b/1073741824).toFixed(2)+' GB' : b > 1048576 ? (b/1048576).toFixed(2)+' MB' : (b/1024).toFixed(2)+' KB';
// Stats polling
async function updateStats() {
  try {
    const res = await fetch('/api/stats');
    const data = await res.json();
    $('stat-total').textContent = fmtNum(data.total_requests);
    $('stat-blocked').textContent = fmtNum(data.blocked_requests);
    $('stat-uptime').textContent = fmtUptime(data.uptime);
    $('stat-goroutines').textContent = data.goroutines + ' goroutines';
    const totalCache = data.cache_hits + data.cache_misses;
    const rate = totalCache > 0 ? ((data.cache_hits / totalCache) * 100).toFixed(1) : 0;
    $('stat-hitrate').textContent = rate + '%';
    $('stat-cache-detail').textContent = fmtNum(data.cache_hits) + ' hits / ' + fmtNum(data.cache_misses) + ' misses';
  } catch(e) {}
}
async function updateCacheStats() {
  try {
    const res = await fetch('/api/cache/stats');
    const data = await res.json();
    $('cache-entries').textContent = fmtNum(data.entries);
    $('cache-size').textContent = fmtBytes(data.current_size_bytes);
    $('cache-hits').textContent = fmtNum(data.hits);
    $('cache-evictions').textContent = fmtNum(data.evictions);
    const pct = data.max_size_bytes > 0 ? (data.current_size_bytes / data.max_size_bytes * 100).toFixed(1) : 0;
    $('cache-bar').style.width = pct + '%';
  } catch(e) {}
}
function fmtUptime(sec) {
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = Math.floor(sec % 60);
  if (d > 0) return d+'d '+h+'h';
  if (h > 0) return h+'h '+m+'m';
  return m+'m '+s+'s';
}
// File editor
async function loadFile() {
  const res = await fetch('/api/file/' + encodeURIComponent($('file').value));
  if (!res.ok) throw new Error('Error cargando archivo');
  $('editor').value = await res.text();
}
async function saveFile() {
  const res = await fetch('/api/file/' + encodeURIComponent($('file').value), {
    method: 'PUT',
    body: $('editor').value
  });
  if (!res.ok) throw new Error('Error guardando');
  $('last-save').textContent = 'Guardado: ' + new Date().toLocaleTimeString();
  await loadFile();
}
async function reloadRules() {
  const res = await fetch('/api/rules');
  const data = await res.json();
  console.log('Reglas recargadas:', data);
  $('last-save').textContent = 'Reglas recargadas: ' + new Date().toLocaleTimeString();
}
async function clearCache() {
  if (!confirm('Vaciar toda la cache?')) return;
  await fetch('/api/cache/clear', { method: 'POST' });
  updateCacheStats();
}
$('load').onclick = () => loadFile().catch(e => alert(e));
$('save').onclick = () => saveFile().catch(e => alert(e));
$('reload').onclick = () => reloadRules();
$('file').onchange = () => loadFile();
$('clear-cache').onclick = () => clearCache();
// Live log
const logEl = $('log');
const maxLines = 500;
let lines = [];
function renderLine(obj) {
  const div = document.createElement('div');
  div.className = 'log-line';
  const actionClass = ['cache_hit','cache_store','blocked_domain','blocked_keyword','mitm','bypass_mitm'].includes(obj.action) ? obj.action : '';
  div.innerHTML = '<span class="log-time">' + obj.time.split('T')[1].split('.')[0] + '</span> ' +
    '<span class="log-action ' + actionClass + '">' + obj.action + '</span> ' +
    '<span class="log-url">' + obj.method + ' ' + obj.host + '</span>';
  return div;
}
// SSE
const es = new EventSource('/api/events');
es.onmessage = (ev) => {
  try {
    const obj = JSON.parse(ev.data);
    const line = renderLine(obj);
    logEl.appendChild(line);
    lines.push(line);
    if (lines.length > maxLines) {
      logEl.removeChild(lines.shift());
    }
    logEl.scrollTop = logEl.scrollHeight;
    $('log-count').textContent = lines.length + ' lineas';
    $('conn-status').textContent = 'Conectado a eventos';
    $('conn-status').previousElementSibling.style.background = 'var(--success)';
  } catch(e) {}
};
es.onerror = () => {
  $('conn-status').textContent = 'Reconectando...';
  $('conn-status').previousElementSibling.style.background = 'var(--danger)';
};
$('clear-log').onclick = () => {
  logEl.innerHTML = '';
  lines = [];
  $('log-count').textContent = '0 lineas';
};
// Init
loadFile().catch(() => {});
updateStats();
updateCacheStats();
setInterval(updateStats, 2000);
setInterval(updateCacheStats, 5000);
</script>
</body>
</html>`
