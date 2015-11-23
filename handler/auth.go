package handler

import (
	"net/http"
	"strings"
	"time"

	"github.com/yosssi/ace"
	"golang.org/x/net/context"

	prf "github.com/micro/explorer-srv/proto/profile"
	token "github.com/micro/explorer-srv/proto/token"
	user "github.com/micro/explorer-srv/proto/user"
	"github.com/micro/explorer-web/session"
	"github.com/micro/go-micro/client"
	uuid "github.com/streadway/simpleuuid"
)

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
