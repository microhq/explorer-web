package handler

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	sjson "github.com/bitly/go-simplejson"

	// for markdown
	"github.com/microcosm-cc/bluemonday"
	"github.com/russross/blackfriday"

	"github.com/gorilla/mux"
	"github.com/yosssi/ace"
	"golang.org/x/net/context"

	"github.com/micro/explorer-web/session"
	"github.com/micro/go-micro/client"

	org "github.com/micro/explorer-srv/proto/organization"
	prf "github.com/micro/explorer-srv/proto/profile"
	search "github.com/micro/explorer-srv/proto/search"
	srv "github.com/micro/explorer-srv/proto/service"
	token "github.com/micro/explorer-srv/proto/token"
	user "github.com/micro/explorer-srv/proto/user"
	uuid "github.com/streadway/simpleuuid"
)

var (
	re = regexp.MustCompile(`^([a-z]+)\[([0-9]+)\]([a-z]+)$`)

	templateDir = "templates"
	opts        *ace.Options
)

type Pager struct {
	Prev      string
	Next      string
	PrevState string
	NextState string
}

func init() {
	opts = ace.InitializeOptions(nil)
	opts.BaseDir = templateDir
	opts.DynamicReload = true
	opts.FuncMap = template.FuncMap{
		"TimeAgo": func(t int64) string {
			return timeAgo(t)
		},
		"TimeAgoIF": func(t json.Number) string {
			i, _ := t.Float64()
			return timeAgo(int64(i))
		},
		"Date": func(t int64) string {
			return date(t)
		},
	}
}

func getPager(u *url.URL, page, limit, items int) *Pager {
	pager := &Pager{}

	if page == 0 || page == 1 {
		pager.Prev = "#"
		pager.PrevState = "disabled"
	} else {
		prev := u
		vars := prev.Query()
		vars.Set("page", strconv.Itoa(page-1))
		prev.RawQuery = vars.Encode()
		pager.Prev = prev.RequestURI()
	}

	if items < limit {
		pager.Next = "#"
		pager.NextState = "disabled"
	} else {
		next := u
		vars := next.Query()
		vars.Set("page", strconv.Itoa(page+1))
		next.RawQuery = vars.Encode()
		pager.Next = next.RequestURI()
	}

	return pager
}

func getPageOffset(p string, limit int) (int, int) {
	page, err := strconv.Atoi(p)
	if err != nil {
		page = 1
	}

	if page > 20 {
		page = 20
	}

	next := page - 1
	if page == 1 {
		next = 0
	}

	offset := next * limit
	return page, offset
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

func date(t int64) string {
	d := time.Unix(t, 0)
	return d.Format("2 Jan 2006")
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

func DeleteService(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	profile := strings.ToLower(vars["profile"])
	service := strings.ToLower(vars["service"])

	if len(profile) == 0 || len(service) == 0 {
		NotFound(w, r)
		return
	}

	// get profile
	preq := client.NewRequest("go.micro.srv.explorer", "Profile.Search", &prf.SearchRequest{
		Name:  profile,
		Limit: 1,
	})
	prsp := &prf.SearchResponse{}
	if err := client.Call(context.Background(), preq, prsp); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}
	if prsp.Profiles == nil || len(prsp.Profiles) == 0 {
		NotFound(w, r)
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
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}

	usrr := session.User(r)

	if len(rsp.Services) == 0 || usrr != rsp.Services[0].Owner {
		NotFound(w, r)
		return
	}

	if r.Method == "POST" {
		// delete from database
		dreq := client.NewRequest("go.micro.srv.explorer", "Service.Delete", &srv.DeleteRequest{
			Id: rsp.Services[0].Id,
		})
		drsp := &srv.DeleteResponse{}
		if err := client.Call(context.Background(), dreq, drsp); err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, r.Referer(), 302)
			return
		}
		// delete from search indexes
		sreq := client.NewRequest("go.micro.srv.explorer", "Search.Delete", &search.DeleteRequest{
			Index: "service",
			Type:  "service",
			Id:    rsp.Services[0].Id,
		})
		srsp := &srv.DeleteResponse{}
		client.Call(context.Background(), sreq, srsp)

		// TODO: delete versions
		http.Redirect(w, r, "/", 302)
	}
}

func Home(w http.ResponseWriter, r *http.Request) {
	usrr := session.User(r)

	req := client.NewRequest("go.micro.srv.explorer", "Service.Search", &srv.SearchRequest{
		Owner: usrr,
		Limit: 10,
	})
	rsp := &srv.SearchResponse{}
	if err := client.Call(context.Background(), req, rsp); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}

	ereq := client.NewRequest("go.micro.srv.explorer", "Service.Search", &srv.SearchRequest{
		Limit: 10,
	})
	ersp := &srv.SearchResponse{}
	if err := client.Call(context.Background(), ereq, ersp); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}

	tpl, err := ace.Load("layout", "home", opts)
	if err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, "/", 302)
		return
	}
	if err := tpl.Execute(w, struct {
		User     string
		Alert    *session.Alert
		Services []*srv.Service
		Explore  []*srv.Service
	}{usrr, session.GetAlert(w, r), rsp.Services, ersp.Services}); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, "/", 302)
		return
	}
}

func Index(w http.ResponseWriter, r *http.Request) {
	req := client.NewRequest("go.micro.srv.explorer", "Service.Search", &srv.SearchRequest{
		Limit: 10,
	})
	rsp := &srv.SearchResponse{}
	if err := client.Call(context.Background(), req, rsp); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}

	tpl, err := ace.Load("layout", "index", opts)
	if err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, "/", 302)
		return
	}
	if err := tpl.Execute(w, struct {
		User     string
		Alert    *session.Alert
		Services []*srv.Service
	}{session.User(r), session.GetAlert(w, r), rsp.Services}); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, "/", 302)
		return
	}
}

func Landing(w http.ResponseWriter, r *http.Request) {
	tpl, err := ace.Load("landing", "", opts)
	if err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, "/", 302)
		return
	}
	if err := tpl.Execute(w, struct {
		User  string
		Alert *session.Alert
	}{session.User(r), session.GetAlert(w, r)}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		tpl, err := ace.Load("layout", "login", opts)
		if err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, "/", 302)
			return
		}
		if err := tpl.Execute(w, struct {
			User  string
			Alert *session.Alert
		}{session.User(r), session.GetAlert(w, r)}); err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, "/", 302)
			return
		}
	} else if r.Method == "POST" {
		r.ParseForm()
		username := strings.ToLower(r.Form.Get("username"))
		password := r.Form.Get("password")
		if len(username) == 0 || len(password) == 0 {
			session.SetAlert(w, r, "Username or password can't be blank", "error")
			http.Redirect(w, r, r.Referer(), 302)
			return
		}
		if err := session.Login(w, r, username, password); err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, "/", 302)
			return
		}
		http.Redirect(w, r, "/", 302)
	}
}

func Logout(w http.ResponseWriter, r *http.Request) {
	if err := session.Logout(w, r); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
	}
	http.Redirect(w, r, r.Referer(), 302)
}

func NotFound(w http.ResponseWriter, r *http.Request) {
	tpl, err := ace.Load("layout", "404", opts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := tpl.Execute(w, map[string]string{"User": session.User(r)}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func NewOrganization(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		tpl, err := ace.Load("layout", "newOrganization", opts)
		if err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, "/", 302)
			return
		}
		if err := tpl.Execute(w, struct {
			User  string
			Alert *session.Alert
		}{session.User(r), session.GetAlert(w, r)}); err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, "/", 302)
			return
		}
	} else if r.Method == "POST" {
		r.ParseForm()
		owner := strings.ToLower(r.Form.Get("owner"))
		name := strings.ToLower(r.Form.Get("name"))
		email := strings.ToLower(r.Form.Get("email"))

		// create org
		id, err := uuid.NewTime(time.Now())
		if err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, r.Referer(), 302)
			return
		}

		orgg := &org.Organization{
			Id:      id.String(),
			Name:    name,
			Owner:   owner,
			Email:   email,
			Created: time.Now().Unix(),
			Updated: time.Now().Unix(),
		}

		if err := validateOrg(orgg); err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, r.Referer(), 302)
			return
		}

		// get profile
		preq := client.NewRequest("go.micro.srv.explorer", "Profile.Search", &prf.SearchRequest{
			Name:  name,
			Limit: 1,
		})
		prsp := &prf.SearchResponse{}
		if err := client.Call(context.Background(), preq, prsp); err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, r.Referer(), 302)
			return
		}

		if len(prsp.Profiles) != 0 {
			session.SetAlert(w, r, "Organization or user already exists", "error")
			http.Redirect(w, r, r.Referer(), 302)
			return
		}

		// create org
		req := client.NewRequest("go.micro.srv.explorer", "Organization.Create", &org.CreateRequest{
			Organization: orgg,
		})
		rsp := &org.CreateResponse{}
		if err := client.Call(context.Background(), req, rsp); err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, r.Referer(), 302)
			return
		}

		// create org profile
		pcreq := client.NewRequest("go.micro.srv.explorer", "Profile.Create", &prf.CreateRequest{
			Profile: &prf.Profile{
				Id:    id.String(),
				Name:  name,
				Owner: owner,
				Type:  1,
			},
		})
		pcrsp := &prf.CreateResponse{}
		if err := client.Call(context.Background(), pcreq, pcrsp); err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, r.Referer(), 302)
			return
		}

		// create search record
		b, _ := json.Marshal(orgg)
		sreq := client.NewRequest("go.micro.srv.explorer", "Search.Create", &search.CreateRequest{
			Document: &search.Document{
				Index: "organization",
				Type:  "organization",
				Id:    orgg.Id,
				Data:  string(b),
			},
		})
		srsp := &search.CreateResponse{}
		client.Call(context.Background(), sreq, srsp)

		http.Redirect(w, r, fmt.Sprintf("/%s", name), 302)
	}
}

func NewService(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		tpl, err := ace.Load("layout", "newService", opts)
		if err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, "/", 302)
			return
		}
		if err := tpl.Execute(w, struct {
			User  string
			Alert *session.Alert
		}{session.User(r), session.GetAlert(w, r)}); err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, "/", 302)
			return
		}
	} else if r.Method == "POST" {
		r.ParseForm()
		owner := strings.ToLower(r.Form.Get("owner"))
		name := strings.ToLower(r.Form.Get("name"))
		desc := r.Form.Get("description")
		url := r.Form.Get("website")
		readme := r.Form.Get("readme")

		// create service
		id, err := uuid.NewTime(time.Now())
		if err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, r.Referer(), 302)
			return
		}

		svc := &srv.Service{
			Id:          id.String(),
			Name:        name,
			Owner:       owner,
			Description: desc,
			Url:         url,
			Readme:      readme,
			Created:     time.Now().Unix(),
			Updated:     time.Now().Unix(),
		}

		if err := validateService(svc); err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, r.Referer(), 302)
			return
		}

		req := client.NewRequest("go.micro.srv.explorer", "Service.Create", &srv.CreateRequest{
			Service: svc,
		})
		rsp := &srv.CreateResponse{}
		if err := client.Call(context.Background(), req, rsp); err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, r.Referer(), 302)
			return
		}

		// create search record
		b, _ := json.Marshal(svc)
		sreq := client.NewRequest("go.micro.srv.explorer", "Search.Create", &search.CreateRequest{
			Document: &search.Document{
				Index: "service",
				Type:  "service",
				Id:    svc.Id,
				Data:  string(b),
			},
		})
		srsp := &search.CreateResponse{}
		client.Call(context.Background(), sreq, srsp)

		// create version
		vid, err := uuid.NewTime(time.Now())
		if err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, r.Referer(), 302)
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
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, r.Referer(), 302)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("/%s/%s", owner, name), 302)
	}
}

func Profile(w http.ResponseWriter, r *http.Request) {
	// load profile
	vars := mux.Vars(r)
	profile := vars["profile"]

	if len(profile) == 0 {
		NotFound(w, r)
		return
	}
	// get profile
	preq := client.NewRequest("go.micro.srv.explorer", "Profile.Search", &prf.SearchRequest{
		Name:  profile,
		Limit: 1,
	})
	prsp := &prf.SearchResponse{}
	if err := client.Call(context.Background(), preq, prsp); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}
	if prsp.Profiles == nil || len(prsp.Profiles) == 0 {
		NotFound(w, r)
		return
	}

	// get services
	req := client.NewRequest("go.micro.srv.explorer", "Service.Search", &srv.SearchRequest{
		Owner: profile,
		Limit: 10,
	})
	rsp := &srv.SearchResponse{}
	if err := client.Call(context.Background(), req, rsp); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}

	tpl, err := ace.Load("layout", "profile", opts)
	if err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, "/", 302)
		return
	}
	if err := tpl.Execute(w, struct {
		User     string
		Alert    *session.Alert
		Profile  *prf.Profile
		Services []*srv.Service
	}{session.User(r), session.GetAlert(w, r), prsp.Profiles[0], rsp.Services}); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, "/", 302)
		return
	}
}

func Service(w http.ResponseWriter, r *http.Request) {
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
		NotFound(w, r)
		return
	}
	// get profile
	preq := client.NewRequest("go.micro.srv.explorer", "Profile.Search", &prf.SearchRequest{
		Name:  profile,
		Limit: 1,
	})
	prsp := &prf.SearchResponse{}
	if err := client.Call(context.Background(), preq, prsp); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}
	if prsp.Profiles == nil || len(prsp.Profiles) == 0 {
		NotFound(w, r)
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
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}
	if rsp.Services == nil || len(rsp.Services) == 0 {
		NotFound(w, r)
		return
	}

	vreq := client.NewRequest("go.micro.srv.explorer", "Service.SearchVersion", &srv.SearchVersionRequest{
		ServiceId: rsp.Services[0].Id,
		Version:   version,
		Limit:     1,
	})
	vrsp := &srv.SearchVersionResponse{}
	if err := client.Call(context.Background(), vreq, vrsp); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, r.Referer(), 302)
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
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, "/", 302)
		return
	}

	unsafe := blackfriday.MarkdownCommon([]byte(rsp.Services[0].Readme))
	readme := bluemonday.UGCPolicy().SanitizeBytes(unsafe)

	if err := tpl.Execute(w, struct {
		User    string
		Readme  string
		Alert   *session.Alert
		Service *srv.Service
		Version *srv.Version
	}{session.User(r), string(readme), session.GetAlert(w, r), rsp.Services[0], ver}); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, "/", 302)
		return
	}
}

func Redirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/", 302)
}

func Search(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	p, o := getPageOffset(r.Form.Get("p"), 20)

	q := r.Form.Get("q")
	if len(q) == 0 {
		session.SetAlert(w, r, "query cannot be blank", "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}

	req := client.NewRequest("go.micro.srv.explorer", "Search.Search", &search.SearchRequest{
		Index:  "service",
		Type:   "service",
		Query:  q,
		Limit:  20,
		Offset: int64(o),
	})
	rsp := &search.SearchResponse{}
	if err := client.Call(context.Background(), req, rsp); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}

	var results []map[string]interface{}
	for _, doc := range rsp.Documents {
		j, err := sjson.NewJson([]byte(doc.Data))
		if err == nil {
			if res, err := j.Map(); err == nil {
				results = append(results, res)
			}
		}
	}

	var pager *Pager
	if len(results) == 20 || !(p < 2) {
		pager = getPager(r.URL, p, 20, len(results))
	}
	// get search results
	tpl, err := ace.Load("layout", "results", opts)
	if err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, "/", 302)
		return
	}
	if err := tpl.Execute(w, struct {
		User    string
		Alert   *session.Alert
		Pager   *Pager
		Results []map[string]interface{}
	}{session.User(r), session.GetAlert(w, r), pager, results}); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, "/", 302)
		return
	}
}

// User signup page
func Signup(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		tpl, err := ace.Load("layout", "signup", opts)
		if err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, "/", 302)
			return
		}
		if err := tpl.Execute(w, struct {
			User  string
			Alert *session.Alert
		}{session.User(r), session.GetAlert(w, r)}); err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, "/", 302)
			return
		}
	} else if r.Method == "POST" {
		r.ParseForm()
		username := strings.ToLower(r.Form.Get("username"))
		password := r.Form.Get("password")
		email := strings.ToLower(r.Form.Get("email"))
		invite := r.Form.Get("token")

		// validation
		if err := validateSignup(username, password, email, invite); err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, r.Referer(), 302)
			return
		}

		treq := client.NewRequest("go.micro.srv.explorer", "Token.Search", &token.SearchRequest{
			Namespace: "invite",
			Name:      invite,
			Limit:     1,
		})
		trsp := &token.SearchResponse{}
		if err := client.Call(context.Background(), treq, trsp); err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, r.Referer(), 302)
			return
		}

		if trsp.Tokens == nil || len(trsp.Tokens) == 0 {
			session.SetAlert(w, r, "Invite token not found", "error")
			http.Redirect(w, r, r.Referer(), 302)
			return
		}

		id, err := uuid.NewTime(time.Now())
		if err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, r.Referer(), 302)
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
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, r.Referer(), 302)
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
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, r.Referer(), 302)
			return
		}

		// success!
		// login
		if err := session.Login(w, r, username, password); err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, r.Referer(), 302)
			return
		}

		tdreq := client.NewRequest("go.micro.srv.explorer", "Token.Delete", &token.DeleteRequest{
			Id: trsp.Tokens[0].Id,
		})
		tdrsp := &token.DeleteResponse{}
		client.Call(context.Background(), tdreq, tdrsp)

		http.Redirect(w, r, "/", 302)
	}
}
