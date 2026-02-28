package data

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-ldap/ldap/v3"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
)

// LdapUser represents a user fetched from LDAP
type LdapUser struct {
	Username string
	Nickname string
	Realname string
	Email    string
	Mobile   string
	DN       string
}

// LdapClient handles LDAP connections and queries for portal user sync
type LdapClient struct {
	host          string
	port          string
	useTLS        bool
	skipTLSVerify bool
	bindDN        string
	bindPassword  string
	baseDN        string
	searchFilter  string
	attrUsername  string
	attrNickname string
	attrRealname string
	attrEmail    string
	attrMobile   string
	log          *log.Helper
}

// NewLdapClient creates a new LDAP client from environment variables
func NewLdapClient(ctx *bootstrap.Context) *LdapClient {
	return &LdapClient{
		host:          ldapEnv("PORTAL_LDAP_HOST", ""),
		port:          ldapEnv("PORTAL_LDAP_PORT", "389"),
		useTLS:        ldapEnv("PORTAL_LDAP_USE_TLS", "false") == "true",
		skipTLSVerify: ldapEnv("PORTAL_LDAP_SKIP_TLS_VERIFY", "false") == "true",
		bindDN:        ldapEnv("PORTAL_LDAP_BIND_DN", ""),
		bindPassword:  ldapEnv("PORTAL_LDAP_BIND_PASSWORD", ""),
		baseDN:        ldapEnv("PORTAL_LDAP_BASE_DN", ""),
		searchFilter:  ldapEnv("PORTAL_LDAP_SEARCH_FILTER", "(objectClass=person)"),
		attrUsername:  ldapEnv("PORTAL_LDAP_ATTR_USERNAME", "sAMAccountName"),
		attrNickname: ldapEnv("PORTAL_LDAP_ATTR_NICKNAME", "givenName"),
		attrRealname: ldapEnv("PORTAL_LDAP_ATTR_REALNAME", "displayName"),
		attrEmail:    ldapEnv("PORTAL_LDAP_ATTR_EMAIL", "mail"),
		attrMobile:   ldapEnv("PORTAL_LDAP_ATTR_MOBILE", "mobile"),
		log:          ctx.NewLoggerHelper("ldap/data/admin-service"),
	}
}

// IsConfigured returns true if LDAP host and base DN are set
func (c *LdapClient) IsConfigured() bool {
	return c.host != "" && c.baseDN != ""
}

// FetchUsers connects to LDAP, searches for users, and returns mapped results
func (c *LdapClient) FetchUsers(_ context.Context) ([]LdapUser, error) {
	if !c.IsConfigured() {
		return nil, fmt.Errorf("LDAP is not configured")
	}

	scheme := "ldap"
	if c.useTLS {
		scheme = "ldaps"
	}
	url := fmt.Sprintf("%s://%s:%s", scheme, c.host, c.port)

	var conn *ldap.Conn
	var err error

	if c.useTLS {
		conn, err = ldap.DialURL(url, ldap.DialWithTLSConfig(&tls.Config{
			InsecureSkipVerify: c.skipTLSVerify, //nolint:gosec
		}))
	} else {
		conn, err = ldap.DialURL(url)
	}
	if err != nil {
		c.log.Errorf("failed to connect to LDAP: %v", err)
		return nil, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}
	defer conn.Close()

	if c.bindDN != "" {
		err = conn.Bind(c.bindDN, c.bindPassword)
		if err != nil {
			c.log.Errorf("failed to bind to LDAP: %v", err)
			return nil, fmt.Errorf("failed to bind to LDAP: %w", err)
		}
	}

	attributes := []string{
		"dn",
		c.attrUsername,
		c.attrNickname,
		c.attrRealname,
		c.attrEmail,
		c.attrMobile,
	}

	searchReq := ldap.NewSearchRequest(
		c.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,     // no size limit
		0,     // no time limit
		false, // types only
		c.searchFilter,
		attributes,
		nil,
	)

	result, err := conn.SearchWithPaging(searchReq, 500)
	if err != nil {
		c.log.Errorf("LDAP search failed: %v", err)
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	users := make([]LdapUser, 0, len(result.Entries))
	for _, entry := range result.Entries {
		u := LdapUser{
			Username: entry.GetAttributeValue(c.attrUsername),
			Nickname: entry.GetAttributeValue(c.attrNickname),
			Realname: entry.GetAttributeValue(c.attrRealname),
			Email:    entry.GetAttributeValue(c.attrEmail),
			Mobile:   entry.GetAttributeValue(c.attrMobile),
			DN:       entry.DN,
		}

		// Skip entries without a username
		if u.Username == "" {
			c.log.Warnf("skipping LDAP entry with no username: %s", entry.DN)
			continue
		}

		users = append(users, u)
	}

	c.log.Infof("fetched %d users from LDAP", len(users))
	return users, nil
}

func ldapEnv(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}
