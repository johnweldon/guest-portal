package main

import (
	"html/template"
	"log"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/urfave/negroni"

	portal "github.com/johnweldon/guest-portal"
)

var (
	listen    = ":12380"
	public    = "public"
	templates = "templates"
	user      = "ubnt"
	pass      = "ubnt"
	unifi     = "https://unifi:8443/"
)

func main() {
	if p := os.Getenv("PORT"); p != "" {
		listen = ":" + p
	}
	if p := os.Getenv("PUBLIC_DIR"); p != "" {
		public = p
	}
	if t := os.Getenv("TEMPLATE_DIR"); t != "" {
		templates = t
	}
	if u := os.Getenv("UNIFI_USER"); u != "" {
		user = u
	}
	if p := os.Getenv("UNIFI_PASS"); p != "" {
		pass = p
	}
	if u := os.Getenv("UNIFI_URL"); u != "" {
		unifi = u
	}

	log.Printf("configuration:\nPUBLIC_DIR=%q\nTEMPLATE_DIR=%q\nUNIFI_USER=%q\nUNIFI_URL=%q", public, templates, user, unifi)

	tmpl := template.Must(template.ParseGlob(path.Join(templates, "*.html")))
	n := negroni.New(
		negroni.NewRecovery(),
		negroni.NewStatic(http.Dir(public)))

	mux := http.NewServeMux()
	mux.Handle("/guest/s/default/", portal.NewGuestHandler(user, pass, unifi, tmpl))
	n.UseHandler(mux)

	s := &http.Server{
		Addr:           listen,
		Handler:        n,
		ReadTimeout:    15 * time.Second,
		WriteTimeout:   15 * time.Second,
		MaxHeaderBytes: 1 << 16,
	}

	log.Printf("listening on %s\n", listen)
	log.Fatal(s.ListenAndServe())
}
