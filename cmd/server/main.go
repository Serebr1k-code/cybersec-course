// Command server runs the CTF learning-tree backend (API + static frontend).
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"learningtree/internal/api"
	"learningtree/internal/auth"
	"learningtree/internal/content"
	"learningtree/internal/progress"
)

func main() {
	addr := flag.String("addr", ":8090", "listen address")
	contentDir := flag.String("content", "content", "directory with markdown lessons")
	dataDir := flag.String("data", "data", "directory for user progress")
	staticDir := flag.String("static", "frontend/dist", "built frontend directory")
	flag.Parse()

	store := content.NewStore(*contentDir)
	if err := store.Load(); err != nil {
		log.Fatalf("failed to load content: %v", err)
	}
	tree := store.Tree()
	log.Printf("loaded %d lessons across %d categories", tree.Total, len(tree.Categories))

	prog := progress.NewStore(*dataDir)

	// Server-side accounts: users.json + a persisted HMAC key so sessions
	// survive a restart. When the key cannot be created we fall back to
	// anonymous-only mode rather than refusing to boot.
	var opts []api.Option
	authStore := auth.NewStore(*dataDir)
	secret, err := auth.LoadOrCreateSecret(filepath.Join(*dataDir, "session.key"))
	if err != nil {
		log.Printf("warning: session key unavailable (%v); accounts disabled", err)
	} else {
		opts = append(opts, api.WithAuth(authStore, auth.NewSessions(secret, auth.DefaultSessionTTL)))
	}

	srv := api.New(store, prog, *staticDir, opts...)

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           logRequests(srv.Handler()),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("listening on http://localhost%s  (static: %s)", *addr, *staticDir)
	if err := httpSrv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		if os.Getenv("LT_QUIET") == "" {
			log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
		}
	})
}
