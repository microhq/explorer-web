package main

import (
	"fmt"
	"html/template"
	"net/http"
	"sync"
	"time"

	// for markdown
	"github.com/microcosm-cc/bluemonday"
	"github.com/russross/blackfriday"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/yosssi/ace"
	"golang.org/x/net/context"

	prf "github.com/myodc/explorer-srv/proto/profile"
	srv "github.com/myodc/explorer-srv/proto/service"
	user "github.com/myodc/explorer-srv/proto/user"
	"github.com/myodc/go-micro/client"
	"github.com/myodc/go-micro/cmd"
	uuid "github.com/streadway/simpleuuid"
)

const (
	sessionName = "X-Micro-Session"
)

var (
	templateDir = "templates"
	opts        *ace.Options

	mtx        sync.RWMutex
	sessionMap = map[*http.Request]*user.Session{}
)

func init() {
	opts = ace.InitializeOptions(nil)
	opts.BaseDir = templateDir
	opts.DynamicReload = true
	opts.FuncMap = template.FuncMap{
		"TimeAgo": func(t int64) string {
			return timeAgo(t)
		},
	}
}

func timeAgo(t int64) string {
	d := time.Unix(t, 0)
	timeAgo := ""
	startDate := time.Now().Unix()
	deltaMinutes := float64(startDate-d.Unix()) / 60.0
	if deltaMinutes <= 523440 { // less than 363 days
		timeAgo = fmt.Sprintf("%s ago", distanceOfTime(deltaMinutes))
	} else {
		timeAgo = d.Format("2 Jan")
	}

	return timeAgo
}

func distanceOfTime(minutes float64) string {
	switch {
	case minutes < 1:
		return fmt.Sprintf("%d secs", int(minutes*60))
	case minutes < 59:
		return fmt.Sprintf("%d minutes", int(minutes))
	case minutes < 90:
		return "about an hour"
	case minutes < 120:
		return "almost 2 hours"
	case minutes < 1080:
		return fmt.Sprintf("%d hours", int(minutes/60))
	case minutes < 1680:
		return "about a day"
	case minutes < 2160:
		return "more than a day"
	case minutes < 2520:
		return "almost 2 days"
	case minutes < 2880:
		return "about 2 days"
	default:
		return fmt.Sprintf("%d days", int(minutes/1440))
	}

	return ""
}

func getSession(w http.ResponseWriter, r *http.Request) *user.Session {
	c, err := r.Cookie(sessionName)
	if err != nil {
		return nil
	}
	req := client.NewRequest("go.micro.srv.explorer", "User.ReadSession", &user.ReadSessionRequest{
		SessionId: c.Value,
	})
	rsp := &user.ReadSessionResponse{}
	if err := client.Call(context.Background(), req, rsp); err != nil {
		http.SetCookie(w, sessions.NewCookie(sessionName, "deleted", &sessions.Options{
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
		}))
		return nil
	}
	return rsp.Session
}

func delSession(r *http.Request) {
	c, err := r.Cookie(sessionName)
	if err != nil {
		return
	}
	req := client.NewRequest("go.micro.srv.explorer", "User.Logout", &user.LogoutRequest{
		SessionId: c.Value,
	})
	rsp := &user.LogoutResponse{}
	client.Call(context.Background(), req, rsp)
}

func usr(r *http.Request) string {
	mtx.RLock()
	s, ok := sessionMap[r]
	mtx.RUnlock()
	if ok {
		return s.Username
	}
	return ""
}

// if the user is authorized "fn" is executed otherwise "afn" is
func auth(fn, afn func(w http.ResponseWriter, r *http.Request)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if s := getSession(w, r); s != nil {
			mtx.Lock()
			sessionMap[r] = s
			mtx.Unlock()

			fn(w, r)

			mtx.Lock()
			delete(sessionMap, r)
			mtx.Unlock()
		} else {
			afn(w, r)
		}
	}
}

func deleteServiceHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	profile := vars["profile"]
	service := vars["service"]

	if len(profile) == 0 || len(service) == 0 {
		notFoundHandler(w, r)
		return
	}

	// get profile
	preq := client.NewRequest("go.micro.srv.explorer", "Profile.Search", &prf.SearchRequest{
		Name: profile,
	})
	prsp := &prf.SearchResponse{}
	if err := client.Call(context.Background(), preq, prsp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if prsp.Profiles == nil || len(prsp.Profiles) == 0 {
		notFoundHandler(w, r)
		return
	}

	// get service
	req := client.NewRequest("go.micro.srv.explorer", "Service.Search", &srv.SearchRequest{
		Name:  service,
		Owner: profile,
		Limit: 1,
	})
	rsp := &srv.SearchResponse{}
	if err := client.Call(context.Background(), req, rsp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	usrr := usr(r)

	if len(rsp.Services) == 0 || usrr != rsp.Services[0].Owner {
		notFoundHandler(w, r)
		return
	}

	if r.Method == "POST" {
		req := client.NewRequest("go.micro.srv.explorer", "Service.Delete", &srv.DeleteRequest{
			Id: rsp.Services[0].Id,
		})
		rsp := &srv.DeleteResponse{}
		if err := client.Call(context.Background(), req, rsp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/", 302)
	}
}

func editProfileHandler(w http.ResponseWriter, r *http.Request) {
	usrr := usr(r)

	preq := client.NewRequest("go.micro.srv.explorer", "Profile.Search", &prf.SearchRequest{
		Name: usrr,
	})
	prsp := &prf.SearchResponse{}
	if err := client.Call(context.Background(), preq, prsp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if prsp.Profiles == nil || len(prsp.Profiles) == 0 {
		notFoundHandler(w, r)
		return
	}

	if r.Method == "GET" {
		tpl, err := ace.Load("layout", "editProfile", opts)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := tpl.Execute(w, struct {
			User    string
			Profile *prf.Profile
		}{usr(r), prsp.Profiles[0]}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else if r.Method == "POST" {
		r.ParseForm()
		prof := prsp.Profiles[0]
		prof.DisplayName = r.Form.Get("name")
		prof.Blurb = r.Form.Get("blurb")
		prof.Url = r.Form.Get("url")
		prof.Location = r.Form.Get("location")

		preq := client.NewRequest("go.micro.srv.explorer", "Profile.Update", &prf.UpdateRequest{
			Profile: prof,
		})
		prsp := &prf.SearchResponse{}
		if err := client.Call(context.Background(), preq, prsp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, r.Referer(), 302)
	}
}

func editServiceHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	profile := vars["profile"]
	service := vars["service"]

	if len(profile) == 0 || len(service) == 0 {
		notFoundHandler(w, r)
		return
	}

	// get profile
	preq := client.NewRequest("go.micro.srv.explorer", "Profile.Search", &prf.SearchRequest{
		Name: profile,
	})
	prsp := &prf.SearchResponse{}
	if err := client.Call(context.Background(), preq, prsp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if prsp.Profiles == nil || len(prsp.Profiles) == 0 {
		notFoundHandler(w, r)
		return
	}

	// get service
	req := client.NewRequest("go.micro.srv.explorer", "Service.Search", &srv.SearchRequest{
		Name:  service,
		Owner: profile,
		Limit: 1,
	})
	rsp := &srv.SearchResponse{}
	if err := client.Call(context.Background(), req, rsp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	usrr := usr(r)

	if len(rsp.Services) == 0 || usrr != rsp.Services[0].Owner {
		notFoundHandler(w, r)
		return
	}

	if r.Method == "GET" {
		tpl, err := ace.Load("layout", "editService", opts)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := tpl.Execute(w, struct {
			User    string
			Service *srv.Service
		}{usr(r), rsp.Services[0]}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else if r.Method == "POST" {
		r.ParseForm()
		owner := r.Form.Get("owner")
		name := r.Form.Get("name")
		desc := r.Form.Get("description")
		url := r.Form.Get("url")
		readme := r.Form.Get("readme")

		// VALIDATE

		req := client.NewRequest("go.micro.srv.explorer", "Service.Update", &srv.UpdateRequest{
			Service: &srv.Service{
				Id:          rsp.Services[0].Id,
				Name:        name,
				Owner:       owner,
				Description: desc,
				Url:         url,
				Readme:      readme,
			},
		})
		rsp := &srv.UpdateResponse{}
		if err := client.Call(context.Background(), req, rsp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("/%s/%s", owner, name), 302)
	}
}

func editVersionHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	profile := vars["profile"]
	service := vars["service"]
	version := vars["version"]

	if len(profile) == 0 || len(service) == 0 || len(version) == 0 {
		notFoundHandler(w, r)
		return
	}

	// get profile
	preq := client.NewRequest("go.micro.srv.explorer", "Profile.Search", &prf.SearchRequest{
		Name: profile,
	})
	prsp := &prf.SearchResponse{}
	if err := client.Call(context.Background(), preq, prsp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if prsp.Profiles == nil || len(prsp.Profiles) == 0 {
		notFoundHandler(w, r)
		return
	}

	// get service
	req := client.NewRequest("go.micro.srv.explorer", "Service.Search", &srv.SearchRequest{
		Name:  service,
		Owner: profile,
		Limit: 1,
	})
	rsp := &srv.SearchResponse{}
	if err := client.Call(context.Background(), req, rsp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	usrr := usr(r)

	if len(rsp.Services) == 0 || usrr != rsp.Services[0].Owner {
		notFoundHandler(w, r)
		return
	}

	vreq := client.NewRequest("go.micro.srv.explorer", "Service.SearchVersion", &srv.SearchVersionRequest{
		ServiceId: rsp.Services[0].Id,
		Version:   version,
		Limit:     1,
	})
	vrsp := &srv.SearchVersionResponse{}
	if err := client.Call(context.Background(), vreq, vrsp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if len(vrsp.Versions) == 0 {
		notFoundHandler(w, r)
		return
	}

	if r.Method == "GET" {
		tpl, err := ace.Load("layout", "editVersion", opts)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := tpl.Execute(w, struct {
			User    string
			Service *srv.Service
			Version *srv.Version
		}{usr(r), rsp.Services[0], vrsp.Versions[0]}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else if r.Method == "POST" {
		r.ParseForm()
		/*
			owner := r.Form.Get("owner")
			name := r.Form.Get("name")
			desc := r.Form.Get("description")
			url := r.Form.Get("url")
			readme := r.Form.Get("readme")
		*/
		// VALIDATE

		req := client.NewRequest("go.micro.srv.explorer", "Service.UpdateVersion", &srv.UpdateVersionRequest{
			Version: &srv.Version{
				Id:           vrsp.Versions[0].Id,
				ServiceId:    rsp.Services[0].Id,
				Version:      vrsp.Versions[0].Version,
				Api:          vrsp.Versions[0].Api,
				Sources:      vrsp.Versions[0].Sources,
				Dependencies: vrsp.Versions[0].Dependencies,
				Metadata:     vrsp.Versions[0].Metadata,
			},
		})
		rsp := &srv.UpdateVersionResponse{}
		if err := client.Call(context.Background(), req, rsp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("/%s/%s/version/%s", profile, service, version), 302)
	}
	return
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	usrr := usr(r)

	req := client.NewRequest("go.micro.srv.explorer", "Service.Search", &srv.SearchRequest{
		Owner: usrr,
		Limit: 10,
	})
	rsp := &srv.SearchResponse{}
	if err := client.Call(context.Background(), req, rsp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tpl, err := ace.Load("layout", "home", opts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := tpl.Execute(w, struct {
		User     string
		Services []*srv.Service
	}{usrr, rsp.Services}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	req := client.NewRequest("go.micro.srv.explorer", "Service.Search", &srv.SearchRequest{
		Limit: 10,
	})
	rsp := &srv.SearchResponse{}
	if err := client.Call(context.Background(), req, rsp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tpl, err := ace.Load("layout", "index", opts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := tpl.Execute(w, struct {
		User     string
		Services []*srv.Service
	}{usr(r), rsp.Services}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// GET: render login page
	// POST: login and redirect to home
	if r.Method == "GET" {
		tpl, err := ace.Load("layout", "login", opts)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := tpl.Execute(w, map[string]string{"User": usr(r)}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else if r.Method == "POST" {
		// get username
		// get password
		// bcrypt(pass + salt) == stored
		// if ok
		// kv.Set("user:session"+user, session{time.Now()+7days})
		// http.Redirect(w, r, "/", 302)
		r.ParseForm()
		username := r.Form.Get("username")
		password := r.Form.Get("password")
		if len(username) == 0 || len(password) == 0 {
			http.Redirect(w, r, r.Referer(), 302)
			return
		}
		req := client.NewRequest("go.micro.srv.explorer", "User.Login", &user.LoginRequest{
			Username: username,
			Password: password,
		})
		rsp := &user.LoginResponse{}
		if err := client.Call(context.Background(), req, rsp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		c := sessions.NewCookie(sessionName, rsp.Session.Id, &sessions.Options{
			Path:     "/",
			MaxAge:   int(time.Unix(rsp.Session.Expires, 0).Sub(time.Now()).Seconds()),
			HttpOnly: true,
		})
		http.SetCookie(w, c)
		http.Redirect(w, r, "/", 302)
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	delSession(r)
	http.SetCookie(w, sessions.NewCookie(sessionName, "deleted", &sessions.Options{
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	}))
	http.Redirect(w, r, r.Referer(), 302)
}

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	tpl, err := ace.Load("layout", "404", opts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := tpl.Execute(w, map[string]string{"User": usr(r)}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func newServiceHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		tpl, err := ace.Load("layout", "newService", opts)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := tpl.Execute(w, map[string]string{"User": usr(r)}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else if r.Method == "POST" {
		r.ParseForm()
		owner := r.Form.Get("owner")
		name := r.Form.Get("name")
		desc := r.Form.Get("description")
		url := r.Form.Get("website")
		readme := r.Form.Get("readme")

		// VALIDATE

		id, err := uuid.NewTime(time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		req := client.NewRequest("go.micro.srv.explorer", "Service.Create", &srv.CreateRequest{
			Service: &srv.Service{
				Id:          id.String(),
				Name:        name,
				Owner:       owner,
				Description: desc,
				Url:         url,
				Readme:      readme,
			},
		})
		rsp := &srv.CreateResponse{}
		if err := client.Call(context.Background(), req, rsp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		vid, err := uuid.NewTime(time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		vreq := client.NewRequest("go.micro.srv.explorer", "Service.CreateVersion", &srv.CreateVersionRequest{
			Version: &srv.Version{
				Id:        vid.String(),
				ServiceId: id.String(),
				Version:   "default",
			},
		})
		vrsp := &srv.CreateResponse{}
		if err := client.Call(context.Background(), vreq, vrsp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("/%s/%s", owner, name), 302)
	}
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	// load profile
	vars := mux.Vars(r)
	profile := vars["profile"]

	if len(profile) == 0 {
		notFoundHandler(w, r)
		return
	}
	// get profile
	preq := client.NewRequest("go.micro.srv.explorer", "Profile.Search", &prf.SearchRequest{
		Name: profile,
	})
	prsp := &prf.SearchResponse{}
	if err := client.Call(context.Background(), preq, prsp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if prsp.Profiles == nil || len(prsp.Profiles) == 0 {
		notFoundHandler(w, r)
		return
	}

	// get services
	req := client.NewRequest("go.micro.srv.explorer", "Service.Search", &srv.SearchRequest{
		Owner: profile,
		Limit: 10,
	})
	rsp := &srv.SearchResponse{}
	if err := client.Call(context.Background(), req, rsp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tpl, err := ace.Load("layout", "profile", opts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := tpl.Execute(w, struct {
		User     string
		Profile  *prf.Profile
		Services []*srv.Service
	}{usr(r), prsp.Profiles[0], rsp.Services}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func serviceHandler(w http.ResponseWriter, r *http.Request) {
	// check if service exists
	// check if public or private
	// check if logged in
	// check if has access
	// load service
	vars := mux.Vars(r)
	profile := vars["profile"]
	service := vars["service"]
	version := vars["version"]

	if len(version) == 0 {
		version = "default"
	}

	if len(profile) == 0 || len(service) == 0 {
		notFoundHandler(w, r)
		return
	}
	// get profile
	preq := client.NewRequest("go.micro.srv.explorer", "Profile.Search", &prf.SearchRequest{
		Name: profile,
	})
	prsp := &prf.SearchResponse{}
	if err := client.Call(context.Background(), preq, prsp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if prsp.Profiles == nil || len(prsp.Profiles) == 0 {
		notFoundHandler(w, r)
		return
	}

	// get service
	req := client.NewRequest("go.micro.srv.explorer", "Service.Search", &srv.SearchRequest{
		Name:  service,
		Owner: profile,
		Limit: 1,
	})
	rsp := &srv.SearchResponse{}
	if err := client.Call(context.Background(), req, rsp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if rsp.Services == nil || len(rsp.Services) == 0 {
		notFoundHandler(w, r)
		return
	}

	vreq := client.NewRequest("go.micro.srv.explorer", "Service.SearchVersion", &srv.SearchVersionRequest{
		ServiceId: rsp.Services[0].Id,
		Version:   version,
		Limit:     1,
	})
	vrsp := &srv.SearchVersionResponse{}
	if err := client.Call(context.Background(), vreq, vrsp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	ver := &srv.Version{
		Version: "default",
	}
	if len(vrsp.Versions) == 1 {
		ver = vrsp.Versions[0]
	}

	tpl, err := ace.Load("layout", "service", opts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	unsafe := blackfriday.MarkdownCommon([]byte(rsp.Services[0].Readme))
	readme := bluemonday.UGCPolicy().SanitizeBytes(unsafe)

	if err := tpl.Execute(w, struct {
		User    string
		Readme  string
		Service *srv.Service
		Version *srv.Version
	}{usr(r), string(readme), rsp.Services[0], ver}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func redirectHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/", 302)
}

func searchHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	q := r.Form.Get("q")
	if len(q) == 0 {
		http.Redirect(w, r, r.Referer(), 302)
		return
	}
	// get search results
	tpl, err := ace.Load("layout", "results", opts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := tpl.Execute(w, map[string]string{"User": usr(r)}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// User signup page
func signupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		tpl, err := ace.Load("layout", "signup", opts)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := tpl.Execute(w, map[string]string{"User": usr(r)}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else if r.Method == "POST" {
		r.ParseForm()
		username := r.Form.Get("username")
		password := r.Form.Get("password")
		email := r.Form.Get("email")
		cpass := r.Form.Get("confirm")

		if len(username) == 0 {
			http.Redirect(w, r, r.Referer(), 302)
			return
		}
		if len(password) == 0 {
			http.Redirect(w, r, r.Referer(), 302)
			return
		}
		if len(email) == 0 {
			http.Redirect(w, r, r.Referer(), 302)
			return
		}
		if len(cpass) == 0 {
			http.Redirect(w, r, r.Referer(), 302)
			return
		}
		if cpass != password {
			http.Redirect(w, r, r.Referer(), 302)
			return
		}
		id, err := uuid.NewTime(time.Now())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// create user
		req := client.NewRequest("go.micro.srv.explorer", "User.Create", &user.CreateRequest{
			User: &user.User{
				Id:       id.String(),
				Username: username,
				Email:    email,
			},
			Password: password,
		})
		rsp := &user.CreateResponse{}
		if err := client.Call(context.Background(), req, rsp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		preq := client.NewRequest("go.micro.srv.explorer", "Profile.Create", &prf.CreateRequest{
			Profile: &prf.Profile{
				Id:    id.String(),
				Name:  username,
				Owner: username,
			},
		})
		prsp := &prf.CreateResponse{}
		if err := client.Call(context.Background(), preq, prsp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// success!
		// login
		ureq := client.NewRequest("go.micro.srv.explorer", "User.Login", &user.LoginRequest{
			Username: username,
			Email:    email,
			Password: password,
		})
		ursp := &user.LoginResponse{}
		if err := client.Call(context.Background(), ureq, ursp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		c := sessions.NewCookie("X-Micro-Session", ursp.Session.Id, &sessions.Options{
			Path:     "/",
			MaxAge:   int(time.Unix(ursp.Session.Expires, 0).Sub(time.Now()).Seconds()),
			HttpOnly: true,
		})
		http.SetCookie(w, c)
		http.Redirect(w, r, "/", 302)
	}
}

func main() {
	cmd.Init()

	r := mux.NewRouter()

	// index
	r.HandleFunc("/", auth(homeHandler, indexHandler))

	// search
	// add elasticsearch
	r.HandleFunc("/search", auth(searchHandler, searchHandler))

	// auth
	// add an invite system and block actual signups
	r.HandleFunc("/login", auth(redirectHandler, loginHandler))
	r.HandleFunc("/logout", auth(logoutHandler, redirectHandler))
	r.HandleFunc("/signup", auth(redirectHandler, signupHandler))

	// settings
	r.HandleFunc("/settings/profile", auth(editProfileHandler, redirectHandler))

	// create things
	r.HandleFunc("/new/service", auth(newServiceHandler, notFoundHandler))

	// For paying customers
	//r.HandleFunc("/new/version", auth(newServiceHandler, notFoundHandler))

	// do/display things
	r.HandleFunc("/{profile}", auth(profileHandler, profileHandler))
	r.HandleFunc("/{profile}/{service}", auth(serviceHandler, serviceHandler))
	r.HandleFunc("/{profile}/{service}/edit", auth(editServiceHandler, notFoundHandler))
	r.HandleFunc("/{profile}/{service}/delete", auth(deleteServiceHandler, notFoundHandler))
	r.HandleFunc("/{profile}/{service}/version/{version}", auth(serviceHandler, serviceHandler))

	// only allow editing of "default" for free users
	r.HandleFunc("/{profile}/{service}/version/{version}/edit", auth(editVersionHandler, notFoundHandler))

	r.NotFoundHandler = http.HandlerFunc(auth(notFoundHandler, notFoundHandler))

	http.Handle("/", r)
	http.ListenAndServe(":8080", nil)
}
