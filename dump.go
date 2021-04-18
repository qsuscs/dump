package main

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"flag"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

var (
	fConfig      = flag.String("config", "config.json", "path to config file")
	fLogNoPrefix = flag.Bool("log-no-prefix", false,
		"don’t prefix log lines with timestamps (useful for systemd)")
	fAccessLog = flag.String("access-log", "",
		"path to access log file (overriding config)")
	fPath = flag.String("path", "",
		"path to store files at (overriding config)")

	path string
)

func handler(rw http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		rw.Header().Add("Allow", "POST")
		if req.Method == "OPTIONS" {
			rw.WriteHeader(http.StatusNoContent)
		} else {
			http.Error(
				rw,
				http.StatusText(http.StatusMethodNotAllowed),
				http.StatusMethodNotAllowed)
		}
		return
	}

	content, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	sum := md5.Sum(content)
	shortsum := base64.StdEncoding.EncodeToString(sum[:])[:10]

	filename := filepath.Join(path, shortsum)
	file, err := os.OpenFile(filename,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0666)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			http.Error(rw, "File exists", http.StatusConflict)
		} else {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	defer file.Close()

	_, err = file.Write(content)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	u := url.URL{Scheme: req.URL.Scheme, Host: req.Host, Path: shortsum}
	if u.Scheme == "" {
		u.Scheme = "http"
	}
	rw.Write([]byte(u.String() + "\n")) //nolint:errcheck
}

func logger(dst *os.File) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return handlers.CombinedLoggingHandler(dst, next)
	}
}

func forbiddenHandler(rw http.ResponseWriter, _req *http.Request) {
	http.Error(rw, http.StatusText(http.StatusForbidden), http.StatusForbidden)
}

func main() {
	flag.Parse()

	if *fLogNoPrefix {
		log.SetFlags(0)
	}

	cfg, err := readConfig(*fConfig)
	if err != nil {
		log.Fatal(err)
	}

	if *fPath != "" {
		path = *fPath
	} else if cfg.Path != "" {
		path = cfg.Path
	} else {
		log.Fatal("no path configured")
	}

	stat, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		err = os.Mkdir(path, 0640)
		if err != nil {
			log.Fatal(err)
		}
	} else if !stat.IsDir() {
		log.Fatalf("path %s exists and is not a directory", path)
	} else if err != nil {
		log.Fatal(err)
	}

	r := mux.NewRouter()

	accesslog := "-"
	if cfg.AccessLog != "" {
		accesslog = cfg.AccessLog
	}
	if *fAccessLog != "" {
		accesslog = *fAccessLog
	}
	if accesslog == "-" {
		r.Use(logger(os.Stdout))
	} else {
		dst, err := os.OpenFile(accesslog,
			os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0640)
		if err != nil {
			log.Fatal(err)
		}
		r.Use(logger(dst))
	}

	if cfg.Proxy {
		r.Use(handlers.ProxyHeaders)
	}
	basicAuth := basicAuthMiddleware{Users: cfg.BasicAuth}
	r.Handle("/new", basicAuth.Middleware(http.HandlerFunc(handler)))
	r.Path("/").HandlerFunc(forbiddenHandler)
	r.PathPrefix("/").Handler(http.FileServer(http.Dir(cfg.Path)))

	srv := &http.Server{
		Addr:    cfg.Listen,
		Handler: r,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Println(err)
		}
	}()
	log.Println("ready, willing, and able.")

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	log.Println("received interrupt, shutting down …")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("HTTP server Shutdown: %v", err)
	}
	log.Println("goodbye.")
}
