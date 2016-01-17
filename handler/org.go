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

	org "github.com/micro/explorer-srv/proto/organization"
	prf "github.com/micro/explorer-srv/proto/profile"
	search "github.com/micro/explorer-srv/proto/search"
	user "github.com/micro/explorer-srv/proto/user"
	"github.com/micro/explorer-web/session"
	"github.com/micro/go-micro/client"
	uuid "github.com/streadway/simpleuuid"
)

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
				Index: "explorer",
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

func AddOrgMember(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		return
	}

	r.ParseForm()
	name := r.Form.Get("name")

	if len(name) == 0 {
		session.SetAlert(w, r, "Username cannot be blank", "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}

	vars := mux.Vars(r)
	organization := strings.ToLower(vars["organization"])
	usrr := session.User(r)

	// Find organization
	oreq := client.NewRequest("go.micro.srv.explorer", "Organization.Search", &org.SearchRequest{
		Name:  organization,
		Limit: 1, // fix this shit
	})
	orsp := &org.SearchResponse{}
	if err := client.Call(context.Background(), oreq, orsp); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}

	// Are you the owner of org?
	if orsp.Organizations == nil || len(orsp.Organizations) == 0 || orsp.Organizations[0].Owner != usrr {
		NotFound(w, r)
		return
	}

	if name == orsp.Organizations[0].Owner {
		session.SetAlert(w, r, "Cannot add owner as member", "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}

	// Find member
	preq := client.NewRequest("go.micro.srv.explorer", "Organization.SearchMembers", &org.SearchMembersRequest{
		OrgName:  orsp.Organizations[0].Name,
		Username: name,
		Limit:    1,
	})
	prsp := &org.SearchMembersResponse{}
	if err := client.Call(context.Background(), preq, prsp); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}

	// Already a member
	if len(prsp.Members) == 1 {
		session.SetAlert(w, r, "Member already part of organization", "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}

	// Does the user even exist?
	ureq := client.NewRequest("go.micro.srv.explorer", "User.Search", &user.SearchRequest{
		Username: name,
		Limit:    1,
	})
	ursp := &user.SearchResponse{}
	if err := client.Call(context.Background(), ureq, ursp); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}

	// User exists?
	if ursp.Users == nil || len(ursp.Users) == 0 {
		session.SetAlert(w, r, "User not found", "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}

	id, err := uuid.NewTime(time.Now())
	if err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}

	// Create member
	rreq := client.NewRequest("go.micro.srv.explorer", "Organization.CreateMember", &org.CreateMemberRequest{
		Member: &org.Member{
			Id:       id.String(),
			OrgName:  orsp.Organizations[0].Name,
			Username: name,
			Created:  time.Now().Unix(),
			Updated:  time.Now().Unix(),
			Roles:    []string{},
		},
	})
	rrsp := &org.CreateMemberResponse{}
	if err := client.Call(context.Background(), rreq, rrsp); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}

	session.SetAlert(w, r, "Added "+name+" to "+orsp.Organizations[0].Name, "success")
	http.Redirect(w, r, r.Referer(), 302)
}

func DelOrgMember(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		return
	}

	r.ParseForm()
	name := r.Form.Get("name")
	if len(name) == 0 {
		session.SetAlert(w, r, "Member username cannot be blank", "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}

	vars := mux.Vars(r)
	organization := strings.ToLower(vars["organization"])
	usrr := session.User(r)

	// Find organization
	oreq := client.NewRequest("go.micro.srv.explorer", "Organization.Search", &org.SearchRequest{
		Name:  organization,
		Limit: 1, // fix this shit
	})
	orsp := &org.SearchResponse{}
	if err := client.Call(context.Background(), oreq, orsp); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}

	// Are you the owner of the org?
	if orsp.Organizations == nil || len(orsp.Organizations) == 0 || orsp.Organizations[0].Owner != usrr {
		NotFound(w, r)
		return
	}

	// Find member
	preq := client.NewRequest("go.micro.srv.explorer", "Organization.SearchMembers", &org.SearchMembersRequest{
		OrgName:  orsp.Organizations[0].Name,
		Username: name,
		Limit:    1,
	})
	prsp := &org.SearchMembersResponse{}
	if err := client.Call(context.Background(), preq, prsp); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}

	if prsp.Members == nil || len(prsp.Members) == 0 {
		NotFound(w, r)
		return
	}

	// Delete member
	rreq := client.NewRequest("go.micro.srv.explorer", "Organization.DeleteMember", &org.DeleteMemberRequest{
		Id: prsp.Members[0].Id,
	})
	rrsp := &org.DeleteMemberResponse{}
	if err := client.Call(context.Background(), rreq, rrsp); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}

	session.SetAlert(w, r, "Member "+name+" removed from "+orsp.Organizations[0].Name, "success")
	http.Redirect(w, r, r.Referer(), 302)
}

func LeaveOrg(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		return
	}

	vars := mux.Vars(r)
	organization := strings.ToLower(vars["organization"])
	usrr := session.User(r)

	// Find organization
	oreq := client.NewRequest("go.micro.srv.explorer", "Organization.Search", &org.SearchRequest{
		Name:  organization,
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

	// Find member
	preq := client.NewRequest("go.micro.srv.explorer", "Organization.SearchMembers", &org.SearchMembersRequest{
		OrgName:  orsp.Organizations[0].Name,
		Username: usrr,
		Limit:    1,
	})
	prsp := &org.SearchMembersResponse{}
	if err := client.Call(context.Background(), preq, prsp); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}

	if prsp.Members == nil || len(prsp.Members) == 0 {
		NotFound(w, r)
		return
	}

	// Delete member
	rreq := client.NewRequest("go.micro.srv.explorer", "Organization.DeleteMember", &org.DeleteMemberRequest{
		Id: prsp.Members[0].Id,
	})
	rrsp := &org.DeleteMemberResponse{}
	if err := client.Call(context.Background(), rreq, rrsp); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}

	session.SetAlert(w, r, "You have left the organization "+orsp.Organizations[0].Name, "success")
	http.Redirect(w, r, r.Referer(), 302)
}

func ViewOrgMembers(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		return
	}

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
		OrgName: orsp.Organizations[0].Name,
		Limit:   100,
	})
	prsp := &org.SearchMembersResponse{}
	if err := client.Call(context.Background(), preq, prsp); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}

	tpl, err := ace.Load("layout", "viewOrgMembers", opts)
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
}
