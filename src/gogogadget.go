// Go Go Gadget - Network Reachability Tool

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aeden/traceroute"
	"github.com/go-ping/ping"
	"github.com/go-redis/redis/v8"
	"github.com/gosnmp/gosnmp"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

var (
	db          *sql.DB                  // MariaDB connection for storing tasks and results
	redisClient *redis.Client            // Redis client for efficient task queuing
	logger      *logrus.Logger           // Structured logger for detailed logging
	cfg         Config                   // Application configuration loaded from YAML
	apiToken    string                   // API token for secure endpoint authentication
	dbUser      string                   // MariaDB username
	dbPassword  string                   // MariaDB password
	dbName      string                   // MariaDB database name
	serverURL   string                   // Server URL for proxy communication
	taskQueue   = make(chan Task, 100)   // Buffered channel for task distribution
	proxyMu     sync.Mutex               // Mutex to protect proxy status map
	proxyStatus = make(map[string]int64) // Tracks last heartbeat timestamp for proxies
)

// Config represents the application configuration loaded from config.yml
type Config struct {
	PollingInterval int `yaml:"polling_interval_seconds"` // How often proxies poll for tasks
	SNMPTimeout     int `yaml:"snmp_timeout_seconds"`     // Timeout duration for SNMP operations
	MaxTasks        int `yaml:"max_tasks"`                // Maximum number of concurrent tasks
	ScoringWeights  struct {
		PingLatency float64 `yaml:"ping_latency"` // Weight for ping latency in proxy scoring
		HopCount    float64 `yaml:"hop_count"`    // Weight for traceroute hop count
		SNMPSuccess float64 `yaml:"snmp_success"` // Weight for SNMP reachability
		SSHStatus   float64 `yaml:"ssh_status"`   // Weight for SSH port status
	} `yaml:"scoring_weights"`
}

// Task defines the structure for a reachability check request
type Task struct {
	TaskID      string // Unique identifier for the task (e.g., "task-123456789")
	Host        string // Target host to check (e.g., "example.com" or "192.168.1.1")
	Communities string // Comma-separated list of SNMP communities (e.g., "public,private")
	Complete    bool   // Indicates if the task is complete
}

// Result holds the outcome of a proxy's check for a task
type Result struct {
	TaskID    string            `json:"task_id"`    // Matches the task ID
	ProxyName string            `json:"proxy_name"` // Name of the proxy (e.g., "proxy1")
	Result    map[string]string `json:"result"`     // Results of checks (e.g., {"ping": "10ms"})
}

func main() {
	// Parse command-line flags for role, port, proxy name, and config file location
	role := flag.String("role", "server", "Role: server or proxy")
	port := flag.String("port", "8080", "Port to listen on or connect to")
	proxyName := flag.String("proxy-name", "", "Name of the proxy (if role is proxy)")
	configPath := flag.String("config", "/etc/gogogadget/config.yml", "Path to config file")
	flag.Parse()

	// Setup structured logging with JSON format for better traceability
	logger = logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	logFile, _ := os.OpenFile("/var/log/gogogadget.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Failed to open log file: %v\n", err)
		os.Exit(1)
	}
	defer logFile.Close()
	logger.SetOutput(logFile)
	// Easter egg: Playful reference to "Go-go Gadget" for Go language
	logger.Info("Starting Go Go Gadget - Go-go Gadget monitoring!")

	// Load configuration from YAML file
	cfgData, err := os.ReadFile(*configPath)
	if err != nil {
		logger.Fatalf("Failed to read config file %s: %v", *configPath, err)
	}
	if err := yaml.Unmarshal(cfgData, &cfg); err != nil {
		logger.Fatalf("Failed to parse config file: %v", err)
	}
	validateConfig()

	// Load environment variables based on the role
	apiToken = os.Getenv("API_TOKEN")
	if *role == "server" {
		dbUser = os.Getenv("DB_USER")
		dbPassword = os.Getenv("DB_PASSWORD")
		dbName = os.Getenv("DB_NAME")
		checkEnvVars([]string{"API_TOKEN", "DB_USER", "DB_PASSWORD", "DB_NAME"})
	} else if *role == "proxy" {
		serverURL = os.Getenv("SERVER_URL")
		checkEnvVars([]string{"API_TOKEN", "SERVER_URL"})
	} else {
		logger.Fatalf("Invalid role specified: %s", *role)
	}

	// Initialize Redis client for task queuing
	redisClient = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379", // Redis server address
		Password: "",               // No password by default
		DB:       0,                // Default Redis database
	})
	if _, err := redisClient.Ping(context.Background()).Result(); err != nil {
		logger.Fatalf("Failed to connect to Redis: %v", err)
	}
	logger.Info("Redis connection established")

	// Initialize MariaDB connection if running as server
	if *role == "server" {
		dataSource := fmt.Sprintf("%s:%s@tcp(127.0.0.1:3306)/%s?timeout=5s", dbUser, dbPassword, dbName)
		db, err = sql.Open("mysql", dataSource)
		if err != nil {
			logger.Fatalf("Failed to initialize MariaDB connection: %v", err)
		}
		db.SetConnMaxLifetime(5 * time.Minute)
		db.SetMaxOpenConns(10)
		db.SetMaxIdleConns(5)
		defer db.Close()
		if err = db.Ping(); err != nil {
			logger.Fatalf("MariaDB ping failed: %v", err)
		}
		logger.Info("MariaDB connection established")
	}

	// Setup context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server or proxy based on the role
	switch *role {
	case "server":
		startServer(ctx, *port)
	case "proxy":
		if *proxyName == "" {
			logger.Fatal("Proxy name is required for proxy role")
		}
		startProxy(ctx, *port, *proxyName)
	}

	// Handle graceful shutdown on SIGINT or SIGTERM
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	logger.Info("Shutting down Go Go Gadget gracefully")
}

// validateConfig ensures configuration values are valid, setting defaults if necessary
func validateConfig() {
	if cfg.PollingInterval <= 0 {
		cfg.PollingInterval = 5 // Default polling interval
		logger.Warn("Polling interval invalid, using default: 5 seconds")
	}
	if cfg.SNMPTimeout <= 0 {
		cfg.SNMPTimeout = 2 // Default SNMP timeout
		logger.Warn("SNMP timeout invalid, using default: 2 seconds")
	}
	if cfg.MaxTasks <= 0 {
		cfg.MaxTasks = 100 // Default max tasks
		logger.Warn("Max tasks invalid, using default: 100")
	}
	totalWeight := cfg.ScoringWeights.PingLatency + cfg.ScoringWeights.HopCount + cfg.ScoringWeights.SNMPSuccess + cfg.ScoringWeights.SSHStatus
	if totalWeight != 1.0 {
		logger.Warn("Scoring weights do not sum to 1.0, resetting to defaults")
		cfg.ScoringWeights.PingLatency = 0.4
		cfg.ScoringWeights.HopCount = 0.2
		cfg.ScoringWeights.SNMPSuccess = 0.3
		cfg.ScoringWeights.SSHStatus = 0.1
	}
}

// checkEnvVars validates that required environment variables are present
func checkEnvVars(required []string) {
	for _, env := range required {
		if os.Getenv(env) == "" {
			logger.Fatalf("Required environment variable %s is not set", env)
		}
	}
}

// startServer initializes the Go Go Gadget server with HTTP endpoints
func startServer(ctx context.Context, port string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/start-check", authMiddleware(startCheckHandler))     // Endpoint to initiate a check
	mux.HandleFunc("/get-task", authMiddleware(getTaskHandler))           // Endpoint for proxies to fetch tasks
	mux.HandleFunc("/submit-result", authMiddleware(submitResultHandler)) // Endpoint to submit check results
	mux.HandleFunc("/get-results", authMiddleware(getResultsHandler))     // Endpoint to retrieve results
	mux.HandleFunc("/health", authMiddleware(healthHandler))              // Health check endpoint
	mux.HandleFunc("/config", authMiddleware(configHandler))              // Configuration retrieval endpoint
	mux.HandleFunc("/test-check", authMiddleware(testCheckHandler))       // Mock check endpoint for testing

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}
	go func() {
		// Easter egg: GadgetScope activation message
		logger.Info("Go Go Gadget PulseNet!")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Server failed to start: %v", err)
		}
	}()
	<-ctx.Done()
	server.Shutdown(context.Background())
}

// authMiddleware enforces API authentication using a bearer token
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token != "Bearer "+apiToken {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			logger.WithFields(logrus.Fields{"remote_addr": r.RemoteAddr}).Warn("Unauthorized access attempt")
			return
		}
		next(w, r)
	}
}

// startCheckHandler initiates a new reachability check task
func startCheckHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var input struct {
		Host        string   `json:"host"`
		Communities []string `json:"communities"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		logger.WithError(err).Warn("Invalid request body received")
		return
	}
	taskID := fmt.Sprintf("task-%d", time.Now().UnixNano())
	communities := strings.Join(input.Communities, ",")
	// Insert task into MariaDB
	_, err := db.Exec("INSERT INTO tasks (task_id, host, communities) VALUES (?, ?, ?)", taskID, input.Host, communities)
	if err != nil {
		http.Error(w, "Failed to create task", http.StatusInternalServerError)
		logger.WithError(err).Error("Failed to insert task into database")
		return
	}
	// Push task ID to Redis queue
	err = redisClient.LPush(context.Background(), "task_queue", taskID).Err()
	if err != nil {
		logger.WithError(err).Error("Failed to push task to Redis queue")
	}
	logger.WithFields(logrus.Fields{"task_id": taskID, "host": input.Host}).Info("Task created and queued")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"task_id": taskID})
}

// getTaskHandler assigns tasks to proxies from the Redis queue
func getTaskHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	proxyName := r.URL.Query().Get("proxy_name")
	if proxyName == "" {
		http.Error(w, "Missing proxy_name", http.StatusBadRequest)
		return
	}
	proxyMu.Lock()
	proxyStatus[proxyName] = time.Now().Unix() // Update proxy heartbeat
	proxyMu.Unlock()

	// Pop task ID from Redis queue
	taskID, err := redisClient.RPop(context.Background(), "task_queue").Result()
	if err == redis.Nil {
		w.WriteHeader(http.StatusNoContent) // No tasks available
		return
	} else if err != nil {
		http.Error(w, "Queue error", http.StatusInternalServerError)
		logger.WithError(err).Error("Failed to retrieve task from Redis")
		return
	}
	// Fetch task details from MariaDB
	var task Task
	err = db.QueryRow("SELECT task_id, host, communities FROM tasks WHERE task_id = ?", taskID).Scan(&task.TaskID, &task.Host, &task.Communities)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		logger.WithError(err).Error("Failed to fetch task details from database")
		return
	}
	logger.WithFields(logrus.Fields{"task_id": task.TaskID, "proxy_name": proxyName}).Info("Task assigned to proxy")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(task)
}

// submitResultHandler processes and stores check results from proxies
func submitResultHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var result Result
	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		logger.WithError(err).Warn("Invalid result submission body")
		return
	}
	// Convert result map to JSON for storage
	resultJSON, _ := json.Marshal(result.Result)
	// Store result in MariaDB
	_, err := db.Exec("INSERT INTO results (task_id, proxy_name, result) VALUES (?, ?, ?)", result.TaskID, result.ProxyName, resultJSON)
	if err != nil {
		http.Error(w, "Failed to submit result", http.StatusInternalServerError)
		logger.WithError(err).Error("Failed to store result in database")
		return
	}
	// Mark task as complete
	_, err = db.Exec("UPDATE tasks SET complete = TRUE WHERE task_id = ?", result.TaskID)
	if err != nil {
		logger.WithError(err).Warn("Failed to update task status to complete")
	}
	logger.WithFields(logrus.Fields{"task_id": result.TaskID, "proxy_name": result.ProxyName}).Info("Result submitted successfully")
	w.WriteHeader(http.StatusOK)
}

// getResultsHandler retrieves all results for a specific task
func getResultsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	taskID := r.URL.Query().Get("task_id")
	if taskID == "" {
		http.Error(w, "Missing task_id", http.StatusBadRequest)
		return
	}
	// Query all results for the task from MariaDB
	rows, err := db.Query("SELECT proxy_name, result FROM results WHERE task_id = ?", taskID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		logger.WithError(err).Error("Failed to fetch task results")
		return
	}
	defer rows.Close()
	var results []Result
	for rows.Next() {
		var res Result
		var resultJSON []byte
		if err := rows.Scan(&res.ProxyName, &resultJSON); err != nil {
			http.Error(w, "Failed to scan results", http.StatusInternalServerError)
			logger.WithError(err).Error("Error scanning result rows")
			return
		}
		res.TaskID = taskID
		json.Unmarshal(resultJSON, &res.Result)
		results = append(results, res)
	}
	// Check if task is complete
	var complete bool
	db.QueryRow("SELECT complete FROM tasks WHERE task_id = ?", taskID).Scan(&complete)
	if !complete && len(results) == 0 {
		http.Error(w, "Task not complete or no results", http.StatusNotFound)
		return
	}
	logger.WithFields(logrus.Fields{"task_id": taskID, "result_count": len(results)}).Info("Task results retrieved")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// healthHandler provides a health check for the server
func healthHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	dbStatus := "connected"
	if err := db.PingContext(ctx); err != nil {
		dbStatus = "disconnected"
	}
	proxyMu.Lock()
	activeProxies := 0
	now := time.Now().Unix()
	for _, lastSeen := range proxyStatus {
		if now-lastSeen < 60 { // Proxies active in the last minute
			activeProxies++
		}
	}
	proxyMu.Unlock()
	response := map[string]interface{}{
		"status":            "healthy",
		"database":          dbStatus,
		"active_tasks":      getActiveTasks(),
		"connected_proxies": activeProxies,
	}
	logger.WithFields(logrus.Fields(response)).Info("Health status requested")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// configHandler returns the current configuration settings
func configHandler(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"polling_interval_seconds": cfg.PollingInterval,
		"snmp_timeout_seconds":     cfg.SNMPTimeout,
		"max_tasks":                cfg.MaxTasks,
		"scoring_weights":          cfg.ScoringWeights,
	}
	logger.WithFields(logrus.Fields(response)).Info("Configuration requested")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// testCheckHandler simulates a reachability check for testing
func testCheckHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var input struct {
		Host string `json:"host"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		logger.WithError(err).Warn("Invalid test check request body")
		return
	}
	taskID := "mock-task-" + time.Now().Format("20060102150405")
	response := map[string]interface{}{
		"task_id": taskID,
		"results": map[string]string{
			"ping":       "avg_rtt=10ms, packet_loss=0%",
			"traceroute": "hops=3",
			"snmp":       "reachable with community: public",
			"ssh":        "open",
		},
	}
	logger.WithFields(logrus.Fields{"task_id": taskID, "host": input.Host}).Info("Mock test check executed")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// getActiveTasks counts the number of incomplete tasks in the database
func getActiveTasks() int {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM tasks WHERE complete = FALSE").Scan(&count)
	if err != nil {
		logger.WithError(err).Warn("Failed to count active tasks")
		return 0
	}
	return count
}

// getConnectedProxies counts the number of active proxies based on recent heartbeats
func getConnectedProxies() int {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	active := 0
	now := time.Now().Unix()
	for _, lastSeen := range proxyStatus {
		if now-lastSeen < 60 { // Active within the last minute
			active++
		}
	}
	return active
}

// startProxy runs the Go Go Gadget proxy, polling for tasks and sending heartbeats
func startProxy(ctx context.Context, port, proxyName string) {
	ticker := time.NewTicker(time.Duration(cfg.PollingInterval) * time.Second)
	defer ticker.Stop()
	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("Proxy shutting down")
			return
		case <-ticker.C:
			task := pollTasks(serverURL, proxyName)
			if task.TaskID != "" {
				results := performChecks(task)
				submitResult(serverURL, Result{TaskID: task.TaskID, ProxyName: proxyName, Result: results})
			}
		case <-heartbeat.C:
			sendHeartbeat(serverURL, proxyName)
		}
	}
}

// pollTasks fetches a task from the server via HTTP
func pollTasks(serverURL, proxyName string) Task {
	req, err := http.NewRequest("GET", serverURL+"/get-task?proxy_name="+proxyName, nil)
	if err != nil {
		logger.WithError(err).Error("Failed to create task polling request")
		return Task{}
	}
	req.Header.Set("Authorization", "Bearer "+apiToken)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		logger.WithFields(logrus.Fields{
			"error":       err,
			"status_code": resp.StatusCode,
			"proxy_name":  proxyName,
		}).Warn("Failed to poll tasks from server")
		if resp != nil {
			resp.Body.Close()
		}
		return Task{}
	}
	defer resp.Body.Close()
	var task Task
	if err := json.NewDecoder(resp.Body).Decode(&task); err != nil {
		logger.WithError(err).Warn("Failed to decode task response")
		return Task{}
	}
	logger.WithFields(logrus.Fields{"task_id": task.TaskID, "proxy_name": proxyName}).Debug("Task received from server")
	return task
}

// performChecks executes network reachability checks for a task
func performChecks(task Task) map[string]string {
	results := make(map[string]string)
	communities := strings.Split(task.Communities, ",")

	// Perform ICMP Ping check with retries
	for i := 0; i < 3; i++ {
		pinger, err := ping.NewPinger(task.Host)
		if err != nil {
			results["ping"] = fmt.Sprintf("error: %v", err)
			time.Sleep(time.Duration(i) * time.Second)
			continue
		}
		pinger.Count = 5 // Send 5 pings
		pinger.Timeout = 5 * time.Second
		err = pinger.Run()
		if err != nil {
			results["ping"] = fmt.Sprintf("error: %v", err)
			time.Sleep(time.Duration(i) * time.Second)
			continue
		}
		stats := pinger.Statistics()
		results["ping"] = fmt.Sprintf("avg_rtt=%v, packet_loss=%.2f%%", stats.AvgRtt, stats.PacketLoss)
		break
	}

	// Perform Traceroute check with retries
	for i := 0; i < 3; i++ {
		hops, err := traceroute.Traceroute(task.Host, &traceroute.TracerouteOptions{})
		if err != nil {
			results["traceroute"] = fmt.Sprintf("error: %v", err)
			time.Sleep(time.Duration(i) * time.Second)
			continue
		}
		results["traceroute"] = fmt.Sprintf("hops=%d", len(hops))
		break
	}

	// Perform SSH port check with retries
	for i := 0; i < 3; i++ {
		sshStatus := checkPort(task.Host, 22)
		if sshStatus == "closed" && i < 2 {
			time.Sleep(time.Duration(i) * time.Second)
			continue
		}
		results["ssh"] = sshStatus
		break
	}

	// Perform parallel SNMP checks
	// Easter egg: "Go-go Gadget" speed boost comment for Go's concurrency
	// Go-go Gadget speed boost: parallel checks FTW!
	snmpResult := performSNMPChecks(task.Host, communities)
	results["snmp"] = snmpResult

	return results
}

// checkPort tests if a specific port is open on the host
func checkPort(host string, port int) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 2*time.Second)
	if err != nil {
		return "closed"
	}
	conn.Close()
	return "open"
}

// performSNMPChecks runs SNMP checks in parallel for all communities
func performSNMPChecks(host string, communities []string) string {
	resultChan := make(chan string, len(communities))
	var wg sync.WaitGroup

	// Launch goroutines for each community to check in parallel
	for _, community := range communities {
		wg.Add(1)
		go func(comm string) {
			defer wg.Done()
			// Retry logic for SNMP checks
			for i := 0; i < 3; i++ {
				snmp := &gosnmp.GoSNMP{
					Target:    host,
					Port:      161,
					Community: comm,
					Version:   gosnmp.Version2c,
					Timeout:   time.Duration(cfg.SNMPTimeout) * time.Second,
				}
				if err := snmp.Connect(); err != nil {
					time.Sleep(time.Duration(i) * time.Second)
					continue
				}
				defer snmp.Conn.Close()
				if _, err := snmp.Get([]string{".1.3.6.1.2.1.1.1.0"}); err == nil {
					resultChan <- fmt.Sprintf("reachable with community: %s", comm)
					return
				}
				time.Sleep(time.Duration(i) * time.Second)
			}
		}(community)
	}

	// Wait for all goroutines to complete and close the channel
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Return the first successful result or failure message
	select {
	case result := <-resultChan:
		return result
	case <-time.After(10 * time.Second):
		return "no community worked"
	}
}

// submitResult sends check results to the server with retry logic
func submitResult(serverURL string, result Result) {
	for i := 0; i < 3; i++ {
		body, err := json.Marshal(result)
		if err != nil {
			logger.WithError(err).Error("Failed to marshal result JSON")
			return
		}
		req, err := http.NewRequest("POST", serverURL+"/submit-result", strings.NewReader(string(body)))
		if err != nil {
			logger.WithError(err).Error("Failed to create result submission request")
			return
		}
		req.Header.Set("Authorization", "Bearer "+apiToken)
		req.Header.Set("Content-Type", "application/json")
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			logger.WithFields(logrus.Fields{"task_id": result.TaskID, "proxy_name": result.ProxyName}).Debug("Result submitted successfully")
			resp.Body.Close()
			return
		}
		logger.WithFields(logrus.Fields{
			"attempt":     i + 1,
			"error":       err,
			"status_code": resp.StatusCode,
		}).Warn("Failed to submit result, retrying")
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(time.Duration(i+1) * time.Second)
	}
	logger.WithFields(logrus.Fields{"task_id": result.TaskID}).Error("Failed to submit result after 3 retries")
}

// sendHeartbeat sends periodic heartbeats to the server
func sendHeartbeat(serverURL, proxyName string) {
	req, err := http.NewRequest("GET", serverURL+"/get-task?proxy_name="+proxyName, nil)
	if err != nil {
		logger.WithError(err).Error("Failed to create heartbeat request")
		return
	}
	req.Header.Set("Authorization", "Bearer "+apiToken)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logger.WithError(err).Warn("Heartbeat failed for proxy")
		return
	}
	defer resp.Body.Close()
	logger.WithFields(logrus.Fields{"proxy_name": proxyName}).Debug("Heartbeat sent successfully")
}
