package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"auth_service/internal/auth/oauth"

	"golang.org/x/oauth2"
	githuboauth "golang.org/x/oauth2/github"
)

var ErrMissingUserID = errors.New("github user: missing id")

type GitHubProvider struct {
	config *oauth2.Config
}

func NewGitHubProvider(clientID, clientSecret, redirectURL string) *GitHubProvider {
	return &GitHubProvider{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       []string{"user:email"},
			Endpoint:     githuboauth.Endpoint,
		},
	}
}

func (p *GitHubProvider) AuthURL(state string) string {
	return p.config.AuthCodeURL(state)
}

func (p *GitHubProvider) Exchange(ctx context.Context, code string) (*oauth.Token, error) {
	token, err := p.config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("github exchange: %w", err)
	}

	return &oauth.Token{AccessToken: token.AccessToken}, nil
}

func (p *GitHubProvider) FetchUser(ctx context.Context, token *oauth.Token) (*oauth.User, error) {
	client := p.config.Client(ctx, &oauth2.Token{AccessToken: token.AccessToken})

	providerUserID, email, err := fetchGitHubIdentity(ctx, client)
	if err != nil {
		return nil, err
	}

	if email == "" {
		// Нет верифицированного primary email — отдаём EmailVerified: false,
		// вызывающий код (OAuthService.Callback) обязан отказать в
		// логине/линковке в этом случае, а не создавать аккаунт вслепую.
		return &oauth.User{ProviderUserID: providerUserID, EmailVerified: false}, nil
	}

	return &oauth.User{
		ProviderUserID: providerUserID,
		Email:          email,
		EmailVerified:  true,
	}, nil
}

func fetchGitHubIdentity(ctx context.Context, client *http.Client) (providerUserID, email string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", http.NoBody)
	if err != nil {
		return "", "", fmt.Errorf("github build user request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("github fetch user: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			if err == nil {
				err = fmt.Errorf("github fetch user: %w", cerr)
			} else {
				err = fmt.Errorf("%w; github fetch user close: %w", err, cerr)
			}
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("github user: unexpected status %d", resp.StatusCode)
	}

	var user struct {
		ID    int64  `json:"id"`
		Email string `json:"email"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return "", "", fmt.Errorf("github decode user: %w", err)
	}

	if user.ID == 0 {
		return "", "", ErrMissingUserID
	}

	providerUserID = fmt.Sprintf("%d", user.ID)

	// /user отдаёт email только если он публичный. Даже в этом случае
	// GitHub API не гарантирует его verified-статус в этом же ответе —
	// поэтому всегда идём в /user/emails за авторитетным verified=true.
	verifiedEmail, err := fetchGitHubPrimaryVerifiedEmail(ctx, client)
	if err != nil {
		return "", "", err
	}

	return providerUserID, verifiedEmail, nil
}

func fetchGitHubPrimaryVerifiedEmail(ctx context.Context, client *http.Client) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", http.NoBody)
	if err != nil {
		return "", fmt.Errorf("github build emails request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("github fetch emails: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			if err == nil {
				err = fmt.Errorf("github fetch user: %w", cerr)
			} else {
				err = fmt.Errorf("%w; github fetch user close: %w", err, cerr)
			}
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github emails: unexpected status %d", resp.StatusCode)
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", fmt.Errorf("github decode emails: %w", err)
	}

	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}

	return "", nil // нет верифицированного primary email — не ошибка, а сигнал наверх
}
