package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	_ "github.com/mattn/go-sqlite3"

	"netplug-go/internal/app"
	"netplug-go/internal/assets"
	"netplug-go/internal/db"
	"netplug-go/internal/pcq"
	"netplug-go/internal/view"
	"netplug-go/internal/wireguard"
	webstatic "netplug-go/web/static"
)

func main() {
	cfg, err := app.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}

	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		log.Fatal(err)
	}

	sqlDB, err := sql.Open("sqlite3", cfg.DatabaseDSN())
	if err != nil {
		log.Fatal(err)
	}
	defer sqlDB.Close()

	sqlDB.SetConnMaxLifetime(0)
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)

	if err := db.Migrate(sqlDB); err != nil {
		log.Fatal(err)
	}
	if err := db.ApplySchemaPatches(sqlDB); err != nil {
		log.Fatal(err)
	}
	if err := db.BootstrapAdmin(sqlDB); err != nil {
		log.Fatal(err)
	}

	sessionManager := scs.New()
	sessionManager.Lifetime = 14 * 24 * time.Hour
	sessionManager.IdleTimeout = 24 * time.Hour
	sessionManager.Cookie.Name = "netplug_session"
	sessionManager.Cookie.HttpOnly = true
	sessionManager.Cookie.SameSite = http.SameSiteLaxMode
	sessionManager.Cookie.Secure = cfg.CookieSecure

	var svcLog *slog.Logger
	if cfg.Debug {
		svcLog = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}

	svc := &app.Services{
		DB:        sqlDB,
		Sessions:  sessionManager,
		Config:    cfg,
		Logger:    svcLog,
		StartedAt: time.Now(),
	}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	// WireGuard backup encryption (scrypt) can take longer than typical API calls.
	r.Use(middleware.Timeout(90 * time.Second))
	r.Use(sessionManager.LoadAndSave)

	r.Handle("/static/*", http.StripPrefix("/static/", webstatic.Handler()))
	r.Handle("/assets/*", http.StripPrefix("/assets/", assets.Handler()))
	// Backwards-compatible asset path (from the original UI).
	r.Get("/plug-icon.png", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, webstatic.FS(), webstatic.PlugIconPath())
	})

	view.SetPCQDisabled(cfg.PCQDisabled)
	app.RegisterRoutes(r, svc)

	server := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	wgSync := wireguard.NewSyncer(sqlDB, cfg.WGInterface, cfg.WGInterval)
	wgSync.Start()
	defer wgSync.Stop()

	// Best-effort: if WireGuard is configured+enabled, bring the interface up on startup.
	// This should not prevent the UI from starting (e.g. during initial setup, or when wg tools aren't available).
	if _, _, _, _, _, err := wireguard.LoadWireGuardState(sqlDB, cfg.WGInterface, svc.StartedAt); err == nil {
		if res, err := wireguard.ReloadWireGuard(sqlDB, cfg.DataDir, cfg.WGInterface); err != nil {
			log.Printf("wireguard startup: failed to apply config: %v", err)
		} else if !res.Applied {
			log.Printf("wireguard startup: config not applied: %s", res.Text)
		} else {
			log.Printf("wireguard startup: interface is up")
			if !cfg.PCQDisabled {
				if _, err := pcq.Apply(sqlDB, cfg.WGInterface, false, pcq.ApplyOpts{
					Debug:  cfg.Debug,
					Logger: svc.Logger,
				}); err != nil {
					if svc.Logger == nil {
						log.Printf("pcq startup: %v", err)
					}
				}
			}
		}
	}

	log.Printf("netplug (go+htmx) listening on %s", cfg.HTTPAddr)
	go func() {
		if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) && err != nil {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		fmt.Fprintf(os.Stderr, "shutdown error: %v\n", err)
	}
}
