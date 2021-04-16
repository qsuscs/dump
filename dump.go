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

const secret = "fnord"

var (
	fListen = flag.String("listen", ":8001", "where to listen")
	fPath   = flag.String("path", ".", "path to place the uploaded files")
	fProxy  = flag.Bool("proxy", false, "set when running behind a proxy")
)

func handler(rw http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		rw.Header().Add("Allow", "POST")
		if req.Method == "OPTIONS" {
			rw.WriteHeader(http.StatusNoContent)
		} else {
			rw.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}

	if req.Header.Get("Authorization") != secret {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	content, err := io.ReadAll(req.Body)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(err.Error() + "\n"))
		return
	}

	sum := md5.Sum(content)
	shortsum := base64.StdEncoding.EncodeToString(sum[:])[:10]

	filename := filepath.Join(*fPath, shortsum)
	file, err := os.OpenFile(filename,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0666)
	if errors.Is(err, os.ErrExist) {
		rw.WriteHeader(http.StatusConflict)
		rw.Write([]byte("File exists\n"))
		return
	}
	defer file.Close()

	_, err = file.Write(content)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(err.Error() + "\n"))
		return
	}
	u := url.URL{Scheme: "http", Host: req.Host, Path: shortsum}
	rw.Write([]byte(u.String() + "\n"))
}

func logger(next http.Handler) http.Handler {
	return handlers.CombinedLoggingHandler(os.Stdout, next)
}

func main() {
	flag.Parse()

	r := mux.NewRouter()
	r.Use(logger)
	if *fProxy {
		r.Use(handlers.ProxyHeaders)
	}
	r.HandleFunc("/new", handler)
	r.PathPrefix("/").Handler(http.FileServer(http.Dir(*fPath)))

	srv := &http.Server{
		Addr:    *fListen,
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
	srv.Shutdown(ctx)
	log.Println("goodbye.")
}
