package main

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed ui/index.html ui/app.css ui/app.js
var embeddedUI embed.FS

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	serveUIFile(w, "index.html", "text/html; charset=utf-8")
}

func (s *Server) handleCSS(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/app.css" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	serveUIFile(w, "app.css", "text/css; charset=utf-8")
}

func (s *Server) handleJS(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/app.js" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	serveUIFile(w, "app.js", "application/javascript; charset=utf-8")
}

func serveUIFile(w http.ResponseWriter, name, contentType string) {
	body, err := fs.ReadFile(embeddedUI, "ui/"+name)
	if err != nil {
		http.Error(w, "asset not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", contentType)
	_, _ = w.Write(body)
}
