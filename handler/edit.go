package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/yosssi/ace"
	"golang.org/x/net/context"

	"github.com/micro/explorer-web/session"
	"github.com/micro/go-micro/client"

	org "github.com/micro/explorer-srv/proto/organization"
	prf "github.com/micro/explorer-srv/proto/profile"
	search "github.com/micro/explorer-srv/proto/search"
	srv "github.com/micro/explorer-srv/proto/service"
	user "github.com/micro/explorer-srv/proto/user"
)

func EditOrganization(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	organization := strings.ToLower(vars["organization"])
	usrr := session.User(r)

	oreq := client.NewRequest("go.micro.srv.explorer", "Organization.Search", &org.SearchRequest{
		Name:  organization,
		Owner: usrr,
		Limit: 1, // fix this shit
	})
	orsp := &org.SearchResponse{}
	if err := client.Call(context.Background(), oreq, orsp); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}

	if orsp.Organizations == nil || len(orsp.Organizations) == 0 {
		NotFound(w, r)
		return
	}

	preq := client.NewRequest("go.micro.srv.explorer", "Profile.Search", &prf.SearchRequest{
		Name:  organization,
		Owner: usrr,
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

	if r.Method == "GET" {
		tpl, err := ace.Load("layout", "editOrganization", opts)
		if err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, "/", 302)
			return
		}
		if err := tpl.Execute(w, struct {
			User    string
			Alert   *session.Alert
			Profile *prf.Profile
			Org     *org.Organization
		}{session.User(r), session.GetAlert(w, r), prsp.Profiles[0], orsp.Organizations[0]}); err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, "/", 302)
			return
		}
	} else if r.Method == "POST" {
		r.ParseForm()
		prof := prsp.Profiles[0]
		prof.DisplayName = r.Form.Get("name")
		prof.Blurb = r.Form.Get("blurb")
		prof.Url = r.Form.Get("url")
		prof.Location = r.Form.Get("location")

		ureq := client.NewRequest("go.micro.srv.explorer", "Profile.Update", &prf.UpdateRequest{
			Profile: prof,
		})
		ursp := &prf.UpdateResponse{}
		if err := client.Call(context.Background(), ureq, ursp); err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, r.Referer(), 302)
			return
		}
		session.SetAlert(w, r, "Successfully updated", "success")
		http.Redirect(w, r, r.Referer(), 302)
	}
}

func EditOrganizationMembers(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	organization := strings.ToLower(vars["organization"])
	usrr := session.User(r)

	oreq := client.NewRequest("go.micro.srv.explorer", "Organization.Search", &org.SearchRequest{
		Name:  organization,
		Owner: usrr,
		Limit: 1, // fix this shit
	})
	orsp := &org.SearchResponse{}
	if err := client.Call(context.Background(), oreq, orsp); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}

	if orsp.Organizations == nil || len(orsp.Organizations) == 0 {
		NotFound(w, r)
		return
	}

	preq := client.NewRequest("go.micro.srv.explorer", "Organization.SearchMembers", &org.SearchMembersRequest{
		OrgId:  orsp.Organizations[0].Id,
		Limit: 100,
	})
	prsp := &org.SearchMembersResponse{}
	if err := client.Call(context.Background(), preq, prsp); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}

	if r.Method == "GET" {
		tpl, err := ace.Load("layout", "editOrgMembers", opts)
		if err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, "/", 302)
			return
		}
		if err := tpl.Execute(w, struct {
			User    string
			Alert   *session.Alert
			Org     *org.Organization
			Members []*org.Member
		}{
			session.User(r),
			session.GetAlert(w, r),
			orsp.Organizations[0],
			prsp.Members,
		}); err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, "/", 302)
			return
		}
	} else if r.Method == "POST" {
		r.ParseForm()
		session.SetAlert(w, r, "Successfully updated", "success")
		http.Redirect(w, r, r.Referer(), 302)
	}
}

func EditProfile(w http.ResponseWriter, r *http.Request) {
	usrr := session.User(r)

	preq := client.NewRequest("go.micro.srv.explorer", "Profile.Search", &prf.SearchRequest{
		Name:  usrr,
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

	if r.Method == "GET" {
		tpl, err := ace.Load("layout", "editProfile", opts)
		if err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, "/", 302)
			return
		}
		if err := tpl.Execute(w, struct {
			User    string
			Alert   *session.Alert
			Profile *prf.Profile
		}{session.User(r), session.GetAlert(w, r), prsp.Profiles[0]}); err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, "/", 302)
			return
		}
	} else if r.Method == "POST" {
		r.ParseForm()
		prof := prsp.Profiles[0]
		prof.DisplayName = r.Form.Get("name")
		prof.Blurb = r.Form.Get("blurb")
		prof.Url = r.Form.Get("url")
		prof.Location = r.Form.Get("location")

		ureq := client.NewRequest("go.micro.srv.explorer", "Profile.Update", &prf.UpdateRequest{
			Profile: prof,
		})
		ursp := &prf.UpdateResponse{}
		if err := client.Call(context.Background(), ureq, ursp); err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, r.Referer(), 302)
			return
		}
		session.SetAlert(w, r, "Successfully updated", "success")
		http.Redirect(w, r, r.Referer(), 302)
	}
}

func EditAccount(w http.ResponseWriter, r *http.Request) {
	usrr := session.User(r)

	preq := client.NewRequest("go.micro.srv.explorer", "Profile.Search", &prf.SearchRequest{
		Name:  usrr,
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

	ureq := client.NewRequest("go.micro.srv.explorer", "User.Search", &user.SearchRequest{
		Username: usrr,
		Limit:    1,
	})
	ursp := &user.SearchResponse{}
	if err := client.Call(context.Background(), ureq, ursp); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}

	if ursp.Users == nil || len(ursp.Users) == 0 {
		NotFound(w, r)
		return
	}

	if r.Method == "GET" {
		tpl, err := ace.Load("layout", "editAccount", opts)
		if err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, "/", 302)
			return
		}
		if err := tpl.Execute(w, struct {
			User  string
			Email string
			Alert *session.Alert
		}{session.User(r), ursp.Users[0].Email, session.GetAlert(w, r)}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func EditOrganizations(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not supported", http.StatusBadRequest)
		return
	}

	usrr := session.User(r)

	preq := client.NewRequest("go.micro.srv.explorer", "Profile.Search", &prf.SearchRequest{
		Name:  usrr,
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

	oreq := client.NewRequest("go.micro.srv.explorer", "Organization.Search", &org.SearchRequest{
		Owner: usrr,
		Limit: 100, // fix this shit
	})
	orsp := &org.SearchResponse{}
	if err := client.Call(context.Background(), oreq, orsp); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}

	tpl, err := ace.Load("layout", "editOrganizations", opts)
	if err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, "/", 302)
		return
	}
	if err := tpl.Execute(w, struct {
		User  string
		Alert *session.Alert
		Orgs  []*org.Organization
	}{session.User(r), session.GetAlert(w, r), orsp.Organizations}); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, "/", 302)
		return
	}
}

func EditService(w http.ResponseWriter, r *http.Request) {
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

	if r.Method == "GET" {
		tpl, err := ace.Load("layout", "editService", opts)
		if err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, "/", 302)
			return
		}
		if err := tpl.Execute(w, struct {
			User    string
			Alert   *session.Alert
			Service *srv.Service
		}{session.User(r), session.GetAlert(w, r), rsp.Services[0]}); err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, "/", 302)
			return
		}
	} else if r.Method == "POST" {
		r.ParseForm()
		owner := strings.ToLower(r.Form.Get("owner"))
		name := strings.ToLower(r.Form.Get("name"))
		desc := r.Form.Get("description")
		url := r.Form.Get("url")
		readme := r.Form.Get("readme")

		// VALIDATE

		svc := &srv.Service{
			Id:          rsp.Services[0].Id,
			Name:        name,
			Owner:       owner,
			Description: desc,
			Url:         url,
			Readme:      readme,
			Created:     rsp.Services[0].Created,
			Updated:     time.Now().Unix(),
		}

		if err := validateService(svc); err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, r.Referer(), 302)
			return
		}

		sureq := client.NewRequest("go.micro.srv.explorer", "Service.Update", &srv.UpdateRequest{
			Service: svc,
		})
		sursp := &srv.UpdateResponse{}
		if err := client.Call(context.Background(), sureq, sursp); err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, r.Referer(), 302)
			return
		}

		b, _ := json.Marshal(svc)
		ureq := client.NewRequest("go.micro.srv.explorer", "Search.Update", &search.UpdateRequest{
			Document: &search.Document{
				Index: "service",
				Type:  "service",
				Id:    rsp.Services[0].Id,
				Data:  string(b),
			},
		})
		ursp := &srv.UpdateResponse{}
		if err := client.Call(context.Background(), ureq, ursp); err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, r.Referer(), 302)
			return
		}
		http.Redirect(w, r, fmt.Sprintf("/%s/%s", owner, name), 302)
	}
}

func EditVersion(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	profile := strings.ToLower(vars["profile"])
	service := strings.ToLower(vars["service"])
	version := vars["version"]

	if len(profile) == 0 || len(service) == 0 || len(version) == 0 {
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

	if len(vrsp.Versions) == 0 {
		NotFound(w, r)
		return
	}

	if r.Method == "GET" {
		tpl, err := ace.Load("layout", "editVersion", opts)
		if err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, "/", 302)
			return
		}
		if err := tpl.Execute(w, struct {
			User    string
			Alert   *session.Alert
			Service *srv.Service
			Version *srv.Version
		}{session.User(r), session.GetAlert(w, r), rsp.Services[0], vrsp.Versions[0]}); err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, "/", 302)
			return
		}
	} else if r.Method == "POST" {
		r.ParseForm()
		// VALIDATE
		api_desc := r.Form.Get("api_description")
		api_info := r.Form.Get("api_info")

		sources := make(map[string]*srv.Source)
		endpoints := make(map[string]*srv.Endpoint)
		deps := make(map[string]*srv.Dependency)

		for k, v := range r.Form {
			m := re.FindAllStringSubmatch(k, -1)
			if len(m) == 0 {
				continue
			}
			if len(m[0]) != 4 {
				continue
			}
			if len(v) > 1 || len(v) == 0 {
				continue
			}

			switch m[0][1] {
			case "source":
				s, ok := sources[m[0][2]]
				if !ok {
					s = &srv.Source{
						Metadata: make(map[string]string),
					}
				}
				if i := m[0][3]; i == "name" {
					s.Name = v[0]
				} else if i == "type" {
					s.Type = v[0]
				} else {
					s.Metadata[i] = v[0]
				}
				sources[m[0][2]] = s
			case "endpoint":
				s, ok := endpoints[m[0][2]]
				if !ok {
					s = &srv.Endpoint{
						Request:  make(map[string]string),
						Response: make(map[string]string),
						Metadata: make(map[string]string),
					}
				}
				if i := m[0][3]; i == "name" {
					s.Name = v[0]
				} else if i == "request" {
					s.Request["default"] = v[0]
				} else if i == "response" {
					s.Response["default"] = v[0]
				} else {
					s.Metadata[i] = v[0]
				}
				endpoints[m[0][2]] = s
			case "dep":
				s, ok := deps[m[0][2]]
				if !ok {
					s = &srv.Dependency{
						Metadata: make(map[string]string),
					}
				}
				if i := m[0][3]; i == "name" {
					s.Name = v[0]
				} else if i == "type" {
					s.Type = v[0]
				} else {
					s.Metadata[i] = v[0]
				}
				deps[m[0][2]] = s
			}
		}

		api := &srv.API{
			Metadata: map[string]string{
				"info":        api_info,
				"description": api_desc,
			},
		}

		ver := &srv.Version{
			Id:        vrsp.Versions[0].Id,
			ServiceId: rsp.Services[0].Id,
			Version:   vrsp.Versions[0].Version,
			Api:       api,
			Metadata:  vrsp.Versions[0].Metadata,
		}

		for _, ep := range endpoints {
			if len(ep.Name) > 0 {
				api.Endpoints = append(api.Endpoints, ep)
			}
		}

		for _, src := range sources {
			if len(src.Name) > 0 {
				ver.Sources = append(ver.Sources, src)
			}
		}

		for _, dep := range deps {
			if len(dep.Name) > 0 {
				ver.Dependencies = append(ver.Dependencies, dep)
			}
		}

		req := client.NewRequest("go.micro.srv.explorer", "Service.UpdateVersion", &srv.UpdateVersionRequest{
			Version: ver,
		})
		rsp := &srv.UpdateVersionResponse{}
		if err := client.Call(context.Background(), req, rsp); err != nil {
			session.SetAlert(w, r, err.Error(), "error")
			http.Redirect(w, r, r.Referer(), 302)
			return
		}

		http.Redirect(w, r, fmt.Sprintf("/%s/%s/version/%s", profile, service, version), 302)
	}
	return
}
