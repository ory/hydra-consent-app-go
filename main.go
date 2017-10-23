package main

import (
	"context"
	"html/template"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	negronilogrus "github.com/meatballhat/negroni-logrus"
	"github.com/ory/common/env"
	"github.com/ory/hydra/sdk/go/hydra"
	"github.com/ory/hydra/sdk/go/hydra/swagger"
	"github.com/pkg/errors"
	"github.com/urfave/negroni"
	"golang.org/x/oauth2"
)

// This store will be used to save user authentication
var store = sessions.NewCookieStore([]byte("something-very-secret-keep-it-safe"))

// The session is a unique session identifier
const sessionName = "authentication"

// This is the Hydra SDK
var client hydra.SDK

// A state for performing the OAuth 2.0 flow. This is usually not part of a consent app, but in order for the demo
// to make sense, it performs the OAuth 2.0 authorize code flow.
var state = "demostatedemostatedemo"

func main() {
	var err error

	// Initialize the hydra SDK. The defaults work if you started hydra as described in the README.md
	client, err = hydra.NewSDK(&hydra.Configuration{
		ClientID:     env.Getenv("HYDRA_CLIENT_ID", "demo"),
		ClientSecret: env.Getenv("HYDRA_CLIENT_SECRET", "demo"),
		EndpointURL:  env.Getenv("HYDRA_CLUSTER_URL", "http://localhost:4444"),
		Scopes:       []string{"hydra.consent"},
	})
	if err != nil {
		log.Fatalf("Unable to connect to the Hydra SDK because %s", err)
	}

	// Set up a router and some routes
	r := mux.NewRouter()
	r.HandleFunc("/", handleHome)
	r.HandleFunc("/consent", handleConsent)
	r.HandleFunc("/login", handleLogin)
	r.HandleFunc("/callback", handleCallback)

	// Set up a request logger, useful for debugging
	n := negroni.New()
	n.Use(negronilogrus.NewMiddleware())
	n.UseHandler(r)

	// Start http server
	log.Println("Listening on :" + env.Getenv("PORT", "3000"))
	http.ListenAndServe(":"+env.Getenv("PORT", "3000"), n)
}

// handles request at /home - a small page that let's you know what you can do in this app. Usually the first.
// page a user sees.
func handleHome(w http.ResponseWriter, _ *http.Request) {
	var config = client.GetOAuth2Config()
	config.RedirectURL = "http://localhost:4445/callback"
	config.Scopes = []string{"offline", "openid"}

	var authURL = client.GetOAuth2Config().AuthCodeURL(state) + "&nonce=" + state
	renderTemplate(w, "home.html", authURL)
}

// After pressing "click here", the Authorize Code flow is performed and the user is redirected to Hydra. Next, Hydra
// validates the consent request (it's not valid yet) and redirects us to the consent endpoint which we set with `CONSENT_URL=http://localhost:4445/consent`.
func handleConsent(w http.ResponseWriter, r *http.Request) {
	// Get the consent requerst id from the query.
	consentRequestID := r.URL.Query().Get("consent")
	if consentRequestID == "" {
		http.Error(w, errors.New("Consent endpoint was called without a consent request id").Error(), http.StatusBadRequest)
		return
	}

	// Fetch consent information
	consentRequest, response, err := client.GetOAuth2ConsentRequest(consentRequestID)
	if err != nil {
		http.Error(w, errors.Wrap(err, "The consent request endpoint does not respond").Error(), http.StatusBadRequest)
		return
	} else if response.StatusCode != http.StatusOK {
		http.Error(w, errors.Wrapf(err, "Consent request endpoint gave status code %d but expected %d", response.StatusCode, http.StatusOK).Error(), http.StatusBadRequest)
		return
	}

	// This helper checks if the user is already authenticated. If not, we
	// redirect them to the login endpoint.
	user := authenticated(r)
	if user == "" {
		http.Redirect(w, r, "/login?consent="+consentRequestID, http.StatusFound)
		return
	}

	// Apparently, the user is logged in. Now we check if we received POST
	// request, or a GET request.
	if r.Method == "POST" {
		// Ok, apparently the user gave their consent!

		// Parse the HTTP form - required by Go.
		if err := r.ParseForm(); err != nil {
			http.Error(w, errors.Wrap(err, "Could not parse form").Error(), http.StatusBadRequest)
			return
		}

		// Let's check which scopes the user granted.
		var grantedScopes = []string{}
		for key := range r.PostForm {
			// And add each scope to the list of granted scopes.
			grantedScopes = append(grantedScopes, key)
		}

		// Ok, now we accept the consent request.
		response, err := client.AcceptOAuth2ConsentRequest(consentRequestID, swagger.ConsentRequestAcceptance{
			// The subject is a string, usually the user id.
			Subject: user,

			// The scopes our user granted.
			GrantScopes: grantedScopes,

			// Data that will be available on the token introspection and warden endpoints.
			AccessTokenExtra: map[string]interface{}{"foo": "bar"},

			// If we issue an ID token, we can set extra data for that id token here.
			IdTokenExtra: map[string]interface{}{"foo": "baz"},
		})
		if err != nil {
			http.Error(w, errors.Wrap(err, "The accept consent request endpoint encountered a network error").Error(), http.StatusInternalServerError)
			return
		} else if response.StatusCode != http.StatusNoContent {
			http.Error(w, errors.Wrapf(err, "Accept consent request endpoint gave status code %d but expected %d", response.StatusCode, http.StatusNoContent).Error(), http.StatusInternalServerError)
			return
		}

		// Redirect the user back to hydra, and append the consent response! If the user denies request you can
		// either handle the error in the authentication endpoint, or redirect the user back to the original application
		// with:
		//
		//   response, err := client.RejectOAuth2ConsentRequest(consentRequestId, payload)
		http.Redirect(w, r, consentRequest.RedirectUrl, http.StatusFound)
		return
	}

	// We received a get request, so let's show the html site where the user may give consent.
	renderTemplate(w, "consent.html", struct {
		*swagger.OAuth2ConsentRequest
		ConsentRequestID string
	}{OAuth2ConsentRequest: consentRequest, ConsentRequestID: consentRequestID})
}

// The user hits this endpoint if not authenticated. In this example, they can sign in with the credentials
// buzz:lightyear
func handleLogin(w http.ResponseWriter, r *http.Request) {
	consentRequestID := r.URL.Query().Get("consent")

	// Is it a POST request?
	if r.Method == "POST" {
		// Parse the form
		if err := r.ParseForm(); err != nil {
			http.Error(w, errors.Wrap(err, "Could not parse form").Error(), http.StatusBadRequest)
			return
		}

		// Check the user's credentials
		if r.Form.Get("username") != "buzz" || r.Form.Get("password") != "lightyear" {
			http.Error(w, "Provided credentials are wrong, try buzz:lightyear", http.StatusBadRequest)
			return
		}

		// Let's create a session where we store the user id. We can ignore errors from the session store
		// as it will always return a session!
		session, _ := store.Get(r, sessionName)
		session.Values["user"] = "buzz-lightyear"

		// Store the session in the cookie
		if err := store.Save(r, w, session); err != nil {
			http.Error(w, errors.Wrap(err, "Could not persist cookie").Error(), http.StatusBadRequest)
			return
		}

		// Redirect the user back to the consent endpoint. In a normal app, you would probably
		// add some logic here that is triggered when the user actually performs authentication and is not
		// part of the consent flow.
		http.Redirect(w, r, "/consent?consent="+consentRequestID, http.StatusFound)
		return
	}

	// It's a get request, so let's render the template
	renderTemplate(w, "login.html", consentRequestID)
}

// Once the user has given their consent, we will hit this endpoint. Again,
// this is not something that would be included in a traditional consent app,
// but we added it so you can see the data once the consent flow is done.
func handleCallback(w http.ResponseWriter, r *http.Request) {
	// in the real world you should check the state query parameter, but this is omitted for brevity reasons.

	// Exchange the access code for an access (and optionally) a refresh token
	token, err := client.GetOAuth2Config().Exchange(context.Background(), r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, errors.Wrap(err, "Could not exhange token").Error(), http.StatusBadRequest)
		return
	}

	// Render the output
	renderTemplate(w, "callback.html", struct {
		*oauth2.Token
		IDToken interface{}
	}{
		Token:   token,
		IDToken: token.Extra("id_token"),
	})
}

// authenticated checks if our cookie store has a user stored and returns the
// user's name, or an empty string if the user is not yet authenticated.
func authenticated(r *http.Request) string {
	session, _ := store.Get(r, sessionName)
	if u, ok := session.Values["user"]; !ok {
		return ""
	} else if user, ok := u.(string); !ok {
		return ""
	} else {
		return user
	}
}

// renderTemplate is a convenience helper for rendering templates.
func renderTemplate(w http.ResponseWriter, id string, d interface{}) bool {
	if t, err := template.New(id).ParseFiles("./templates/" + id); err != nil {
		http.Error(w, errors.Wrap(err, "Could not render template").Error(), http.StatusInternalServerError)
		return false
	} else if err := t.Execute(w, d); err != nil {
		http.Error(w, errors.Wrap(err, "Could not render template").Error(), http.StatusInternalServerError)
		return false
	}
	return true
}
