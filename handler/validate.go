package handler

import (
	"fmt"
	"regexp"
	"strings"

	org "github.com/micro/explorer-srv/proto/organization"
	srv "github.com/micro/explorer-srv/proto/service"
)

var (
	ure = regexp.MustCompile("^[a-zA-Z0-9_]+$")
	sre = regexp.MustCompile("^[a-z0-9.:-_]+$")
)

func validateEmail(email string) error {
	if len(email) == 0 {
		return fmt.Errorf("Email cannot be blank")
	}
	parts := strings.Split(email, "@")
	if len(parts) != 2 || len(parts[0]) == 0 || len(parts[1]) == 0 {
		return fmt.Errorf("Invalid email address")
	}
	suff := strings.Split(parts[1], ".")
	if len(suff) < 2 {
		return fmt.Errorf("Invalid email address")
	}
	return nil
}

func validateUpdatePassword(old, neu, confirm string) error {
	var thing string
	var blank bool

	switch {
	case len(old) == 0:
		thing = "Old password"
		blank = true
	case len(neu) == 0:
		thing = "New password"
		blank = true
	case len(confirm) == 0:
		thing = "Confirm password"
		blank = true
	}

	if blank {
		return fmt.Errorf("%s cannot be blank", thing)
	}

	if confirm != neu {
		return fmt.Errorf("New password and confirm password do not match")
	}

	if len(neu) < 6 {
		return fmt.Errorf("Password must be 6 or more characters")
	}

	if len(neu) > 255 {
		return fmt.Errorf("Password must be less than 255 characters...sorry we know")
	}

	return nil
}

func validateOrg(orgg *org.Organization) error {
	if len(orgg.Name) == 0 {
		return fmt.Errorf("Organization name cannot be blank")
	}
	if len(orgg.Owner) == 0 {
		return fmt.Errorf("Organization owner cannot be blank")
	}
	if len(orgg.Email) == 0 {
		return fmt.Errorf("Organization email cannot be blank")
	}
	parts := strings.Split(orgg.Email, "@")
	if len(parts) != 2 || len(parts[0]) == 0 || len(parts[1]) == 0 {
		return fmt.Errorf("Invalid email address")
	}
	suff := strings.Split(parts[1], ".")
	if len(suff) < 2 {
		return fmt.Errorf("Invalid email address")
	}
	if !ure.MatchString(orgg.Name) {
		return fmt.Errorf("Organization name can only contain alphanumeric characters and underscores")
	}
	return nil
}

func validateService(service *srv.Service) error {
	// VALIDATE
	if len(service.Name) == 0 {
		return fmt.Errorf("Service name cannot be blank")
	}
	if len(service.Owner) == 0 {
		return fmt.Errorf("Owner cannot be blank")
	}
	if !sre.MatchString(service.Name) {
		return fmt.Errorf("Invalid service name. Must only include alphanumeric characters")
	}
	return nil
}

func validateSignup(username, password, email, invite string) error {
	var thing string
	var blank bool
	switch {
	case len(username) == 0:
		thing = "Username"
		blank = true
	case len(password) == 0:
		thing = "Password"
		blank = true
	case len(email) == 0:
		thing = "Email"
		blank = true
	case len(invite) == 0:
		thing = "Invite token"
		blank = true
	}

	if blank {
		return fmt.Errorf("%s cannot be blank", thing)
	}

	if !ure.MatchString(username) {
		return fmt.Errorf("Username can only contain alphanumeric characters and underscores")
	}

	if len(username) < 2 {
		return fmt.Errorf("Username must be greater or equal to 2 characters")
	}

	if len(username) > 255 {
		return fmt.Errorf("Username cannot be greater than 255 characters")
	}

	switch username {
	case "login", "signup", "logout", "new", "edit", "search", "settings", "profile", "service", "version":
		return fmt.Errorf("Username already taken")
	}

	if len(password) < 6 {
		return fmt.Errorf("Password must be 6 or more characters")
	}

	if len(password) > 255 {
		return fmt.Errorf("Password must be less than 255 characters...sorry we know")
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 || len(parts[0]) == 0 || len(parts[1]) == 0 {
		return fmt.Errorf("Invalid email address")
	}
	suff := strings.Split(parts[1], ".")
	if len(suff) < 2 {
		return fmt.Errorf("Invalid email address")
	}

	return nil
}
