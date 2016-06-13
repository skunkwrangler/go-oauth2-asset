package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"encoding/json"

	"github.com/cloudfoundry-community/go-cfenv"
	"github.com/twinj/uuid"
	"golang.org/x/oauth2"
	"gopkg.in/redis.v3"
)

const ourCookieName = "sess_cookie"
const uaaServiceLabel = "predix-uaa"
const assetServiceLabel = "predix-asset"
const redisServiceTag = "redis"
const zoneHeader = "predix-zone-id"

var clientID, clientSecret, authURL, tokenURL, redirectURL, assetURL, assetZoneID, port,
	userRedirectToUAA, redisHost, redisPass, redisPort string

var scopes = []string{
	"scim.me",
	"uaa.resource",
	"openid",
}

var redisClient *redis.Client

var myConfig = &oauth2.Config{
	Scopes: scopes,
}

// This will attempt to make the call to Asset, provided the token is available and valid.
// Otherwise, kick the user to UAA
func getAssets(w http.ResponseWriter, req *http.Request) {
	//process cookies:
	var sessionCookie *http.Cookie
	cookies := req.Cookies()
	for _, cookie := range cookies {
		log.Printf("Cookie:  %v\n", cookie.Name)
		if strings.EqualFold(cookie.Name, ourCookieName) {
			// We have our guy
			sessionCookie = cookie
			break
		}
	}

	//no cookie?  kick to /authcode
	if sessionCookie == nil {
		// user is 'cold'
		fmt.Printf("No cookie...\n")
		http.Redirect(w, req, userRedirectToUAA, 302)
		return
	}

	cachedToken, err := getTokenFromCache(sessionCookie.Value)
	// Either:  No token in Redis or Redis is broken; token is nil; or it's not valid
	// ¯\_(ツ)_/¯ Just send the user to UAA to do everything over.
	if err != nil || cachedToken == nil || !cachedToken.Valid() {
		log.Printf("Token/cache issue: %v\n", err)
		http.Redirect(w, req, userRedirectToUAA, 302)
		return
	}

	//Elevated *http.Client which will use the *Token
	clientWithToken := myConfig.Client(oauth2.NoContext, cachedToken)

	myRequest, err := http.NewRequest(http.MethodGet, assetURL+"/nodes", nil)

	if err != nil {
		log.Printf("Error: %v\n", err)
		fmt.Fprintf(w, string("Could not make outbound request to asset: %v"), err)
		return
	}

	myRequest.Header.Add("Content-Type", "application/json")
	myRequest.Header.Add(zoneHeader, assetZoneID)

	resp, err := clientWithToken.Do(myRequest)
	defer resp.Body.Close()

	if err != nil {
		log.Printf("Error returned by Asset: %v\n", err)
		fmt.Fprintf(w, string("Error returned by Asset: %v"), err)
		return
	}

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error processing Asset response: %v\n", err)
		fmt.Fprintf(w, string("Error processing Asset response: %v"), err)
		return
	}
	fmt.Fprintf(w, string(content[:]))
}

// Private func to interact with Redis
func getTokenFromCache(cookieUUID string) (*oauth2.Token, error) {
	srlzdToken, err := redisClient.Get(cookieUUID).Result()
	if err != nil {
		return nil, errors.New("Couldn't find the token in Redis!")
	}

	var retVal *oauth2.Token
	err = json.Unmarshal([]byte(srlzdToken), &retVal)

	if retVal == nil {
		return nil, errors.New("Couldn't unmarshall token!")
	}

	return retVal, nil
}

// Private func to:
// 	- turn the UAA authcode into a proper Token;
//  	- generate the uuid for the cookie and Redis;
//	- send the cookie to the user;
//	- cache the Token in Redis using the uuid as the key.
func processOauth(w http.ResponseWriter, req *http.Request) {
	// Request will be of the form:
	//	https://your-app....predix.io/authcode?code=To02XR
	//
	// We want the 'code'
	req.ParseForm()
	authCode := req.FormValue("code")

	// Use the code with the OAuth2 config to get a token
	myToken, err := myConfig.Exchange(oauth2.NoContext, authCode)

	// The code may be invalid or bogus.  Kick the user back to UAA
	if err != nil {
		log.Printf("Exchanging code for token failed: %v\n", err)
		http.Redirect(w, req, userRedirectToUAA, 302)
		return
	}

	// Generate a uuid
	cookieVal := uuid.Formatter(uuid.NewV4(), uuid.CleanHyphen)

	// Setup the cookie and set it
	cookieToSend := &http.Cookie{
		Name:     ourCookieName,
		Value:    cookieVal,
		MaxAge:   0,
		Secure:   false,
		HttpOnly: false,
	}

	http.SetCookie(w, cookieToSend)

	// Serialize token and insert to Redis
	srlzdToken, err := json.Marshal(&myToken)

	err = redisClient.Set(cookieVal, srlzdToken, 0).Err()
	if err != nil {
		log.Println("Could not add token to Redis: %v", err)
	}

	// Send the user back to /assets.  Everything is now in place for GetAssets() function properly and be stateless
	http.Redirect(w, req, "/assets", 302)
	return
}

func init() {
	appEnv, _ := cfenv.Current()
	services := appEnv.Services
	uaaServices, err := services.WithLabel(uaaServiceLabel)
	if err != nil || len(uaaServices) < 1 {
		panic("No UAA service found!!")
	}
	assetServices, err := services.WithLabel(assetServiceLabel)
	if err != nil || len(assetServices) < 1 {
		panic("No asset service found!!")
	}
	redisServices, err := services.WithTag(redisServiceTag)
	if err != nil || len(redisServices) < 1 {
		panic("No Redis service found!!")
	}

	tokenURL = uaaServices[0].Credentials["issuerId"].(string)
	authURL = uaaServices[0].Credentials["uri"].(string) + "/oauth/authorize"

	redirectURL = "https://" + appEnv.ApplicationURIs[0] + "/authcode"

	assetURL = assetServices[0].Credentials["uri"].(string)
	assetZoneID = assetServices[0].Credentials["instanceId"].(string)

	clientID = os.Getenv("CLIENT_ID")
	clientSecret = os.Getenv("CLIENT_SECRET")

	port = os.Getenv("PORT")

	// UAA redirect needs to be in the form of:
	//
	//  https://your_service_guid.uaa.predix.io/oauth/authorize?
	//	client_id=your_client_id&
	//	response_type=code&  <- not arbitrary.  You need a `code` returned for processOauth()
	//	redirect_uri=https://my-app/authcode
	userRedirectToUAA = authURL + "?client_id=" + clientID + "&response_type=code&redirect_uri=" + redirectURL

	// Not the most elegant solution, but I've found the app won't run at all if I rely upon
	//   redisServices[0].Credentials["port"].(string) or redisServices[0].Credentials["port"].(int)
	//   to get the port.  host and password work fine with explicit casting, but I'm rolling them in here because
	//   at least illustrates a switch/case
	for credKey, credVal := range redisServices[0].Credentials {
		switch {
		case strings.EqualFold(credKey, "host"):
			redisHost = credVal.(string)

		case strings.EqualFold(credKey, "port"):
			redisPort = fmt.Sprint(credVal)

		case strings.EqualFold(credKey, "password"):
			redisPass = credVal.(string)
		}
	}

	// Set up the OAuth2 config
	myConfig.ClientID = clientID
	myConfig.ClientSecret = clientSecret
	myConfig.Endpoint.AuthURL = authURL
	myConfig.Endpoint.TokenURL = tokenURL
	myConfig.RedirectURL = redirectURL

	redisClient = redis.NewClient(&redis.Options{
		Addr:     redisHost + ":" + redisPort,
		Password: redisPass,
		DB:       0,
	})

	// Just care about failures, don't need the actual response
	_, err = redisClient.Ping().Result()

	if err != nil {
		log.Printf("Error pinging Redis: %v", err)
	}
}

func main() {
	http.HandleFunc("/assets", getAssets)
	http.HandleFunc("/authcode", processOauth)
	fmt.Printf("Starting server\n\n")
	err := http.ListenAndServe(":"+port, nil)
	if err != nil {
		log.Printf("ListenAndServe: ", err)
	}
}
