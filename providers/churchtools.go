package providers

import (
	"context"
	"fmt"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// ChurchtoolsProvider represents a ChurchTools based Identity Provider
type ChurchtoolsProvider struct {
	*ProviderData
}

var _ Provider = (*ChurchtoolsProvider)(nil)

const churchToolsProviderName = "Churchtools"

// NewChurchtoolsProvider initiates a new ChurchtoolsProvider
func NewChurchtoolsProvider(p *ProviderData) *ChurchtoolsProvider {
	p.setProviderDefaults(providerDefaults{
		name: churchToolsProviderName,
	})

	p.getAuthorizationHeaderFunc = makeOIDCHeader
	return &ChurchtoolsProvider{ProviderData: p}
}

// EnrichSession uses the ChurchTools userinfo endpoint to populate
// the session's email, user, and groups.
func (p *ChurchtoolsProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	// Fallback to ValidateURL if ProfileURL not set for legacy compatibility
	profileURL := p.ValidateURL.String()
	if p.ProfileURL.String() != "" {
		profileURL = p.ProfileURL.String()
	}

	json, err := requests.New(profileURL).
		WithContext(ctx).
		SetHeader("Authorization", tokenTypeBearer+" "+s.AccessToken).
		Do().
		UnmarshalSimpleJSON()
	if err != nil {
		logger.Errorf("failed making request %v", err)
		return err
	}

	groups, err := json.GetPath("groups").StringArray()
	if err == nil {
		for _, group := range groups {
			if group != "" {
				s.Groups = append(s.Groups, group)
			}
		}
	}

	user, err := json.GetPath("id").Int()
	if err != nil {
		return fmt.Errorf("unable to extract id from userinfo endpoint: %v", err)
	}
	s.User = fmt.Sprint(user)

	email, err := json.GetPath("email").String()
	if err != nil {
		return fmt.Errorf("unable to extract email from userinfo endpoint: %v", err)
	}
	s.Email = email

	return nil
}

// ValidateSession validates the AccessToken
func (p *ChurchtoolsProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeOIDCHeader(s.AccessToken))
}
