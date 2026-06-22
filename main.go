package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"sdl-control/config"
	"sdl-control/control"
	"sdl-control/control/store"
	"sdl-control/handlers"
	"strconv"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme/autocert"
)

var Version = "dev"

func main() {
	levelStr := os.Getenv("LOG_LEVEL")
	level, err := log.ParseLevel(strings.ToLower(levelStr))
	if err != nil {
		level = log.InfoLevel // 默认 info
	}
	log.SetLevel(level)
	version := buildVersion()
	log.Infof("sdl-control starting version=%s", version)

	// support overriding config path via CONFIG_PATH env (useful in docker-compose / CI)
	cfgPath := os.Getenv("CONFIG_PATH")
	if cfgPath == "" {
		cfgPath = "config/config.json"
	}
	if _, err := os.Stat(cfgPath); err != nil {
		cfgPath = "config.json"
	}
	log.Infof("Loading config from %s", cfgPath)
	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}
	log.Infof(
		"Config loaded: listen_addr=%s default_domain=%s default_gateway_id=%s domains=%d require_client_cert=%t",
		cfg.ListenAddr,
		cfg.EffectiveDefaultDomain(),
		cfg.DefaultGatewayID,
		len(cfg.Domains),
		cfg.RequireClientCert,
	)

	databaseURL := firstNonEmpty(os.Getenv("DATABASE_URL"), cfg.DatabaseURL)
	var db *sql.DB
	var pgStore *store.Store
	requiredControlVersion, err := store.LatestMigrationVersion("control")
	if err != nil {
		log.Fatalf("resolve required control schema version failed: %v", err)
	}
	if strings.TrimSpace(databaseURL) != "" {
		pgStore, err = openPostgresStore(databaseURL)
		if err != nil {
			log.Fatalf("database initialization failed: %v", err)
		}
		defer pgStore.Close()
		db = pgStore.DB()
	}
	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		if pgStore == nil {
			log.Fatal("DATABASE_URL/database_url is required for `sdl-control migrate`")
		}
		if err := pgStore.ApplyMigrations(); err != nil {
			log.Fatalf("apply database schema migrations failed: %v", err)
		}
		log.Infof("database schema migrations applied through %s", requiredControlVersion)
		return
	}
	if pgStore != nil {
		if err := pgStore.RequireMigration(requiredControlVersion); err != nil {
			log.Fatalf("database schema check failed: %v", err)
		}
	}

	listenAddr := firstNonEmpty(os.Getenv("LISTEN_ADDR"), cfg.ListenAddr)
	if listenAddr == "" {
		listenAddr = ":443"
	}

	// 支持测试模式：如果环境变量 TLS_CERT 和 TLS_KEY 存在，则直接加载本地证书（用于 docker-compose / CI）
	tlsCertPath := firstNonEmpty(os.Getenv("TLS_CERT"), cfg.TLSCertPath)
	tlsKeyPath := firstNonEmpty(os.Getenv("TLS_KEY"), cfg.TLSKeyPath)
	clientCAPath := firstNonEmpty(os.Getenv("TLS_CLIENT_CA"), cfg.ClientCAPath)
	requireClientCert := cfg.RequireClientCert
	if requireClientCertStr := os.Getenv("TLS_REQUIRE_CLIENT_CERT"); requireClientCertStr != "" {
		parsed, err := strconv.ParseBool(requireClientCertStr)
		if err != nil {
			log.Fatalf("invalid TLS_REQUIRE_CLIENT_CERT value: %v", err)
		}
		requireClientCert = parsed
	}

	var tlsConfig *tls.Config
	var autocertHTTPAddr string
	var autocertHTTPHandler http.Handler
	if tlsCertPath != "" && tlsKeyPath != "" {
		log.Infof("Loading TLS cert from env paths: %s, %s", tlsCertPath, tlsKeyPath)
		cert, err := tls.LoadX509KeyPair(tlsCertPath, tlsKeyPath)
		if err != nil {
			log.Fatalf("Failed to load TLS cert/key: %v", err)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}
	} else {
		domain := firstNonEmpty(os.Getenv("AUTOCERT_DOMAIN"), cfg.AutoCertDomain, cfg.EffectiveDefaultDomain())
		if domain == "" {
			log.Fatal("AUTOCERT_DOMAIN/domain is required when TLS cert/key are not provided")
		}
		autocertHTTPAddr = firstNonEmpty(os.Getenv("AUTOCERT_HTTP_ADDR"), cfg.AutoCertHTTPAddr)
		if autocertHTTPAddr == "" {
			autocertHTTPAddr = ":80"
		}
		cacheDir := firstNonEmpty(os.Getenv("CERT_CACHE_DIR"), cfg.CertCacheDir)
		if cacheDir == "" {
			cacheDir = "./cert-cache"
		}

		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(domain),
			Cache:      autocert.DirCache(cacheDir),
			Email:      firstNonEmpty(os.Getenv("AUTOCERT_EMAIL"), cfg.AutoCertEmail),
		}

		tlsConfig = m.TLSConfig()
		tlsConfig.MinVersion = tls.VersionTLS13
		autocertHTTPHandler = m.HTTPHandler(nil)
		log.Infof(
			"ACME enabled for domain=%s, http_challenge_addr=%s, cache_dir=%s",
			domain,
			autocertHTTPAddr,
			cacheDir,
		)
	}
	if clientCAPath != "" {
		clientCA, err := os.ReadFile(clientCAPath)
		if err != nil {
			log.Fatalf("failed to read client CA file: %v", err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(clientCA) {
			log.Fatal("failed to parse client CA PEM")
		}
		tlsConfig.ClientCAs = caPool
		if requireClientCert {
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
		}
		log.Infof("Client certificate verification enabled (required=%t)", requireClientCert)
	}

	// 信号监听
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())

	ctrl, err := control.NewController(cfg, db)
	if err != nil {
		log.Fatalf("create controller failed: %v", err)
	}

	adminSocket := firstNonEmpty(os.Getenv("ADMIN_SOCKET_PATH"), "/tmp/sdl-control-admin.sock")
	if err := handlers.StartAdminUnixServer(ctx, ctrl, adminSocket, version); err != nil {
		log.Fatalf("start admin unix socket failed: %v", err)
	}
	adminHTTPAddr := firstNonEmpty(os.Getenv("ADMIN_HTTP_ADDR"), cfg.AdminHTTPAddr)
	adminHTTPToken := firstNonEmpty(os.Getenv("ADMIN_HTTP_TOKEN"), cfg.AdminHTTPToken)
	if strings.TrimSpace(adminHTTPAddr) != "" {
		if strings.TrimSpace(adminHTTPToken) == "" {
			log.Fatalf("ADMIN_HTTP_TOKEN/admin_http_token is required when admin_http_addr is enabled")
		}
		if err := handlers.StartAdminHTTPServer(ctx, ctrl, adminHTTPAddr, adminHTTPToken, version); err != nil {
			log.Fatalf("start admin http server failed: %v", err)
		}
	}
	if autocertHTTPHandler != nil {
		if err := handlers.StartHTTPServer(ctx, autocertHTTPAddr, autocertHTTPHandler); err != nil {
			log.Fatalf("start autocert http challenge server failed: %v", err)
		}
	}
	go func() {
		<-sigs
		cancel()
		ctrl.Stop()
	}()

	handlers.StartHTTP3Server(ctx, ctrl, listenAddr, tlsConfig)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func buildVersion() string {
	if strings.TrimSpace(Version) != "" && Version != "dev" {
		return Version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := strings.TrimSpace(info.Main.Version); v != "" && v != "(devel)" {
			return v
		}
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" && strings.TrimSpace(setting.Value) != "" {
				rev := strings.TrimSpace(setting.Value)
				if len(rev) > 12 {
					rev = rev[:12]
				}
				return "dev+" + rev
			}
		}
	}
	return "dev"
}

func openPostgresStore(databaseURL string) (*store.Store, error) {
	var pgStore *store.Store
	var err error
	for i := 0; i < 20; i++ {
		pgStore, err = store.Open(databaseURL)
		if err == nil {
			if pingErr := pgStore.DB().Ping(); pingErr == nil {
				return pgStore, nil
			} else {
				err = fmt.Errorf("ping database: %w", pingErr)
			}
			_ = pgStore.Close()
		}
		log.Warnf("Waiting for database to be ready... (%d/20): %v", i+1, err)
		time.Sleep(1 * time.Second)
	}
	return nil, err
}
