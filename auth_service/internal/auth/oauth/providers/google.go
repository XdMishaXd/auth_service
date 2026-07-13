package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"auth_service/internal/auth/oauth"

	"golang.org/x/oauth2"
	googleoauth "golang.org/x/oauth2/google"
)

type GoogleProvider struct {
	config *oauth2.Config
}

func NewGoogleProvider(clientID, clientSecret, redirectURL string) *GoogleProvider {
	return &GoogleProvider{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       []string{"openid", "email", "profile"},
			Endpoint:     googleoauth.Endpoint,
		},
	}
}

func (p *GoogleProvider) AuthURL(state string) string {
	return p.config.AuthCodeURL(state, oauth2.AccessTypeOnline)
}

func (p *GoogleProvider) Exchange(ctx context.Context, code string) (*oauth.OAuthToken, error) {
	token, err := p.config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("google exchange: %w", err)
	}

	return &oauth.OAuthToken{AccessToken: token.AccessToken}, nil
}

func (p *GoogleProvider) FetchUser(ctx context.Context, token *oauth.OAuthToken) (*oauth.OAuthUser, error) {
	client := p.config.Client(ctx, &oauth2.Token{AccessToken: token.AccessToken})

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.googleapis.com/oauth2/v3/userinfo", nil)
	if err != nil {
		return nil, fmt.Errorf("google build userinfo request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("google fetch userinfo: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google userinfo: unexpected status %d", resp.StatusCode)
	}

	var body struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("google decode userinfo: %w", err)
	}

	if body.Sub == "" {
		return nil, fmt.Errorf("google userinfo: missing sub")
	}

	return &oauth.OAuthUser{
		ProviderUserID: body.Sub,
		Email:          body.Email,
		EmailVerified:  body.EmailVerified,
	}, nil
}
