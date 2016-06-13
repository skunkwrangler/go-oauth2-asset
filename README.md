# go-auth2-asset
This is an illustration of how to integrate UAA with an Go app and access platform services (e.g. Asset).

Here is roughly the flow:

1. User requests /assets
2. The function handler for /assets is called and checks to see if the request contains the session cookie.
3. If not, then it redirects the user to UAA using the following URL signature (broken-up to show elements):
   - https://your_service_guid.uaa.predix.io/oauth/authorize?  
     - client_id=my_client_id&
     - response_type=code&
     - redirect_uri=https://my-app/authcode
4. The user logs into UAA; if successful, UAA will obey the `redirect_uri` above and send the user back to https://my-app/authcode
5. The incoming request to /authcode has a `code` query string key and a string value.  This string value is the OAuth2 one-time access code.
6. The [`golang.org/x/oauth2`](https://godoc.org/golang.org/x/oauth2) package provides a [mechanism](https://godoc.org/golang.org/x/oauth2#Config.Exchange) to convert the code to a proper token.
    This token is coined using the app's client credentials.
7. Once the token is created, we cache it in Redis with a uuid key.  We set a cookie with the key and send the user back to /assets (Step 1).
8. The /assets handler can now pull the [`*Token`](https://godoc.org/golang.org/x/oauth2#Token) from Redis and create an [`*http.Client`](https://godoc.org/golang.org/x/oauth2#Config.Client).
9. This `*http.Client` offers some convenience, but we still need to add the `Content-Type=application/json` and `predix-zone-id=your_asset_zone` headers.
10. With these set, we can make the call to Asset and send the raw JSON response to the user.
