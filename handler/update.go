package handler

import (
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"golang.org/x/net/context"

	"github.com/micro/explorer-web/session"
	"github.com/micro/go-micro/client"

	org "github.com/micro/explorer-srv/proto/organization"
	user "github.com/micro/explorer-srv/proto/user"
)

func UpdateOrganizationEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
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

	r.ParseForm()
	email := r.Form.Get("email")

	if err := validateEmail(email); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}

	orgg := orsp.Organizations[0]
	orgg.Email = email

	ureq := client.NewRequest("go.micro.srv.explorer", "Organization.Update", &org.UpdateRequest{
		Organization: orgg,
	})

	ursp := &org.UpdateResponse{}
	if err := client.Call(context.Background(), ureq, ursp); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}
	session.SetAlert(w, r, "Email updated successfully", "success")
	http.Redirect(w, r, r.Referer(), 302)
}

func UpdateEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		return
	}

	usrr := session.User(r)

	preq := client.NewRequest("go.micro.srv.explorer", "User.Search", &user.SearchRequest{
		Username: usrr,
		Limit:    1,
	})
	prsp := &user.SearchResponse{}
	if err := client.Call(context.Background(), preq, prsp); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}
	if len(prsp.Users) == 0 {
		NotFound(w, r)
		return
	}

	r.ParseForm()
	email := r.Form.Get("email")

	if err := validateEmail(email); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}

	usr := prsp.Users[0]
	usr.Email = email

	ureq := client.NewRequest("go.micro.srv.explorer", "User.Update", &user.UpdateRequest{
		User: usr,
	})

	ursp := &user.UpdateResponse{}
	if err := client.Call(context.Background(), ureq, ursp); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}
	session.SetAlert(w, r, "Email updated successfully", "success")
	http.Redirect(w, r, r.Referer(), 302)
}

func UpdatePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		return
	}

	usrr := session.User(r)

	preq := client.NewRequest("go.micro.srv.explorer", "User.Search", &user.SearchRequest{
		Username: usrr,
		Limit:    1,
	})
	prsp := &user.SearchResponse{}
	if err := client.Call(context.Background(), preq, prsp); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}
	if len(prsp.Users) == 0 {
		NotFound(w, r)
		return
	}

	r.ParseForm()
	old := r.Form.Get("pass")
	newPass := r.Form.Get("new_pass")
	confirm := r.Form.Get("confirm_pass")

	if err := validateUpdatePassword(old, newPass, confirm); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}

	prof := prsp.Users[0]

	ureq := client.NewRequest("go.micro.srv.explorer", "User.UpdatePassword", &user.UpdatePasswordRequest{
		UserId:          prof.Id,
		OldPassword:     old,
		NewPassword:     newPass,
		ConfirmPassword: confirm,
	})
	ursp := &user.UpdatePasswordResponse{}
	if err := client.Call(context.Background(), ureq, ursp); err != nil {
		session.SetAlert(w, r, err.Error(), "error")
		http.Redirect(w, r, r.Referer(), 302)
		return
	}
	session.SetAlert(w, r, "Password updated successfully", "success")
	http.Redirect(w, r, r.Referer(), 302)
}
