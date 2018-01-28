package server

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

// HickHubAuth is an authorization service for checking whether a HickHub user is able to connect
// to the server.
type HickHubAuth struct {
	apiURL   string
	adminKey string
}

type subjectResponse struct {
	Subject string `json:"subject"`
}

const subjectPath = "/user/messaging/subject"

// NewHickHubAuth returns a new instance of the hickhub auth service.
func NewHickHubAuth(apiURL, adminKey string) *HickHubAuth {
	return &HickHubAuth{adminKey, apiURL}
}

// Check checks whether the provided client authentication information should allow the user to connect
// and registers the appropriate permissions for the user.
func (h *HickHubAuth) Check(c ClientAuthentication) bool {
	// Get the auth token, and request valid subscriptions from the HickHubAPI
	authToken := c.GetOpts().Authorization

	// Check whether this is the admin auth token, in which case they get to do EVERYTHING
	if authToken == h.adminKey {
		return h.registerAdmin(c)
	}

	return h.registerUser(c, authToken)
}

func (h *HickHubAuth) registerAdmin(c ClientAuthentication) bool {
	perms := new(Permissions)
	perms.Publish = []string{"*"}
	perms.Subscribe = []string{">"}
	perms.Reply = []string{"*"}
	user := &User{
		Permissions: perms,
	}

	c.RegisterUser(user)
	return true
}

func (h *HickHubAuth) registerUser(c ClientAuthentication, authToken string) bool {
	authHeader := fmt.Sprintf("bearer %v", authToken)
	path := h.apiURL + subjectPath

	client := &http.Client{}
	req, err := http.NewRequest("GET", path, nil)
	if err != nil {
		return false
	}
	req.Header.Add("Authorization", authHeader)

	resp, err := client.Do(req)
	if err != nil {
		return false
	}

	// If we got something other than a 200 response, then it isn't authorised
	if resp.StatusCode != 200 {
		return false
	}

	// Get the valid subject name from the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	subjectResponse := new(subjectResponse)
	err = json.Unmarshal(body, subjectResponse)
	if err != nil {
		return false
	}

	// Register the user's permissions based on the valid subject response
	perms := new(Permissions)
	perms.Subscribe = []string{subjectResponse.Subject}
	perms.Reply = []string{subjectResponse.Subject}
	user := &User{
		Permissions: perms,
	}
	c.RegisterUser(user)

	return true
}
