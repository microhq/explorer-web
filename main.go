package main

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/micro/explorer-web/handler"
	"github.com/micro/explorer-web/session"
	"github.com/micro/go-micro/cmd"
)

type Handler struct {
	r *mux.Router
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sess := session.Read(w, r)
	if sess != nil {
		h.r.ServeHTTP(w, r)
		return
	}

	if r.Method == "GET" {
		handler.Landing(w, r)
		return
	}

	switch r.URL.Path {
	case "/login", "/signup":
		h.r.ServeHTTP(w, r)
	default:
		handler.Landing(w, r)
	}
}

// if the user is authorized "fn" is executed otherwise "afn" is
func auth(fn, afn func(w http.ResponseWriter, r *http.Request)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if s := session.Read(w, r); s != nil {
			session.SaveLocal(r, s)
			fn(w, r)
			session.DeleteLocal(r)
		} else {
			afn(w, r)
		}
	}
}

func main() {
	cmd.Init()

	r := mux.NewRouter()

	// index
	r.HandleFunc("/", auth(handler.Home, handler.Index))

	// search
	// add elasticsearch
	r.HandleFunc("/search", auth(handler.Search, handler.Search))

	// auth
	// add an invite system and block actual signups
	r.HandleFunc("/login", auth(handler.Redirect, handler.Login))
	r.HandleFunc("/logout", auth(handler.Logout, handler.Redirect))
	r.HandleFunc("/signup", auth(handler.Redirect, handler.Signup))

	// settings
	r.HandleFunc("/settings/profile", auth(handler.EditProfile, handler.Redirect))
	r.HandleFunc("/settings/account", auth(handler.EditAccount, handler.Redirect))
	r.HandleFunc("/settings/account/password", auth(handler.UpdatePassword, handler.Redirect))

	// create things
	r.HandleFunc("/new/service", auth(handler.NewService, handler.NotFound))

	// For paying customers
	//r.HandleFunc("/new/version", auth(newServiceHandler, notFoundHandler))

	// do/display things
	r.HandleFunc("/{profile}", auth(handler.Profile, handler.Profile))
	r.HandleFunc("/{profile}/{service}", auth(handler.Service, handler.Service))
	r.HandleFunc("/{profile}/{service}/edit", auth(handler.EditService, handler.NotFound))
	r.HandleFunc("/{profile}/{service}/delete", auth(handler.DeleteService, handler.NotFound))
	r.HandleFunc("/{profile}/{service}/version/{version}", auth(handler.Service, handler.Service))

	// only allow editing of "default" for free users
	r.HandleFunc("/{profile}/{service}/version/{version}/edit", auth(handler.EditVersion, handler.NotFound))

	r.NotFoundHandler = http.HandlerFunc(auth(handler.NotFound, handler.NotFound))

	http.Handle("/", r)
	http.ListenAndServe(":8080", &Handler{r})
}
