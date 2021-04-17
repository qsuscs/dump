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
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

var (
	fConfig = flag.String("config", "config.json", "path to config file")

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
	u := url.URL{Scheme: "http", Host: req.Host, Path: shortsum}
	rw.Write([]byte(u.String() + "\n")) //nolint:errcheck
}

func logger(next http.Handler) http.Handler {
	return handlers.CombinedLoggingHandler(os.Stdout, next)
}

func forbiddenHandler(rw http.ResponseWriter, _req *http.Request) {
	http.Error(rw, http.StatusText(http.StatusForbidden), http.StatusForbidden)
}

func main() {
	flag.Parse()

	cfg, err := readConfig(*fConfig)
	if err != nil {
		log.Fatal(err)
	}

	path = cfg.Path

	r := mux.NewRouter()
	r.Use(logger)
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
	signal.Notify(c, os.Interrupt)
	<-c
	log.Println("received interrupt, shutting down …")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("HTTP server Shutdown: %v", err)
	}
	log.Println("goodbye.")
}
