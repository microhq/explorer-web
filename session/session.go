package session

import (
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/sessions"
	"github.com/micro/go-micro/client"
	"golang.org/x/net/context"

	user "github.com/micro/explorer-srv/proto/user"
)

const (
	alertId       = "_s"
	ssid          = "_u"
	sessionHeader = "X-Micro-Session"
)

var (
	mtx        sync.RWMutex
	sessionMap = map[*http.Request]*user.Session{}
	store      = sessions.NewCookieStore([]byte("fuck you"))
)

type Alert struct {
	Type, Message string
}

func SaveLocal(r *http.Request, u *user.Session) {
	mtx.Lock()
	sessionMap[r] = u
	mtx.Unlock()
}

func DeleteLocal(r *http.Request) {
	mtx.Lock()
	delete(sessionMap, r)
	mtx.Unlock()
}

func Read(w http.ResponseWriter, r *http.Request) *user.Session {
	var sessId string
	c, err := r.Cookie(ssid)
	if err == nil {
		sessId = c.Value
	} else if err == http.ErrNoCookie {
		if s := r.Header.Get(sessionHeader); len(s) > 0 {
			sessId = s
		} else {
			return nil
		}
	} else {
		return nil
	}

	req := client.NewRequest("go.micro.srv.explorer", "User.ReadSession", &user.ReadSessionRequest{
		SessionId: sessId,
	})
	rsp := &user.ReadSessionResponse{}
	if err := client.Call(context.Background(), req, rsp); err != nil {
		http.SetCookie(w, sessions.NewCookie(ssid, "deleted", &sessions.Options{
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
		}))
		return nil
	}
	return rsp.Session
}

func Login(w http.ResponseWriter, r *http.Request, username, password string) error {
	req := client.NewRequest("go.micro.srv.explorer", "User.Login", &user.LoginRequest{
		Username: username,
		Password: password,
	})
	rsp := &user.LoginResponse{}
	if err := client.Call(context.Background(), req, rsp); err != nil {
		return err
	}
	c := sessions.NewCookie(ssid, rsp.Session.Id, &sessions.Options{
		Path:     "/",
		MaxAge:   int(time.Unix(rsp.Session.Expires, 0).Sub(time.Now()).Seconds()),
		HttpOnly: true,
	})
	http.SetCookie(w, c)
	return nil
}

func Logout(w http.ResponseWriter, r *http.Request) error {
	c, err := r.Cookie(ssid)
	if err != nil {
		return err
	}
	req := client.NewRequest("go.micro.srv.explorer", "User.Logout", &user.LogoutRequest{
		SessionId: c.Value,
	})
	rsp := &user.LogoutResponse{}
	if err := client.Call(context.Background(), req, rsp); err != nil {
		return err
	}
	http.SetCookie(w, sessions.NewCookie(ssid, "deleted", &sessions.Options{
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	}))
	return nil
}

func User(r *http.Request) string {
	mtx.RLock()
	s, ok := sessionMap[r]
	mtx.RUnlock()
	if ok {
		return s.Username
	}
	return ""
}

func GetAlert(w http.ResponseWriter, r *http.Request) *Alert {
	sess, err := store.Get(r, alertId)
	if err != nil {
		return nil
	}
	defer sess.Save(r, w)

	for _, i := range []string{"info", "error", "success"} {
		f := sess.Flashes(i)
		if f != nil {
			if i == "error" {
				i = "danger"
			}

			return &Alert{
				Type:    i,
				Message: f[0].(string),
			}
		}
	}
	return nil
}

func SetAlert(w http.ResponseWriter, r *http.Request, msg string, typ string) {
	sess, err := store.Get(r, alertId)
	if err != nil {
		return
	}
	sess.AddFlash(msg, typ)
	sess.Save(r, w)
}
