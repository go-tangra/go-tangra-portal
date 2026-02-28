package service

import (
	"context"
	"strings"

	paginationV1 "github.com/tx7do/go-crud/api/gen/go/pagination/v1"
	"github.com/tx7do/go-utils/trans"

	"github.com/go-tangra/go-tangra-portal/app/admin/service/internal/data"

	userV1 "github.com/go-tangra/go-tangra-portal/api/gen/go/user/service/v1"
)

// computeChangedUserFields compares an existing user with LDAP data and returns the list of changed fields
func computeChangedUserFields(existing *userV1.User, ldap *data.LdapUser) []string {
	var changed []string

	if ldap.Username != "" && ldap.Username != existing.GetUsername() {
		changed = append(changed, "username")
	}
	if ldap.Realname != "" && ldap.Realname != existing.GetRealname() {
		changed = append(changed, "realname")
	}
	if ldap.Email != "" && ldap.Email != existing.GetEmail() {
		changed = append(changed, "email")
	}
	if ldap.Mobile != "" && ldap.Mobile != existing.GetMobile() {
		changed = append(changed, "mobile")
	}

	return changed
}

// ldapUserToProto converts LDAP user data to a proto User message
func ldapUserToProto(ldap *data.LdapUser) *userV1.User {
	u := &userV1.User{}
	if ldap.Username != "" {
		u.Username = &ldap.Username
	}
	if ldap.Realname != "" {
		u.Realname = &ldap.Realname
	}
	if ldap.Email != "" {
		u.Email = &ldap.Email
	}
	if ldap.Mobile != "" {
		u.Mobile = &ldap.Mobile
	}
	return u
}

// buildUserPreview generates a sync preview by comparing LDAP entries against existing users
func (s *UserService) buildUserPreview(ctx context.Context) (*userV1.LdapSyncPreviewResponse, []data.LdapUser, error) {
	ldapUsers, err := s.ldapClient.FetchUsers(ctx)
	if err != nil {
		return nil, nil, err
	}

	// List all existing users (no paging)
	existingResp, err := s.userRepo.List(ctx, &paginationV1.PagingRequest{NoPaging: trans.Ptr(true)})
	if err != nil {
		return nil, nil, err
	}

	// Build lookup maps
	byUsername := make(map[string]*userV1.User)
	byEmail := make(map[string]*userV1.User)
	for _, u := range existingResp.Items {
		if u.GetUsername() != "" {
			byUsername[strings.ToLower(u.GetUsername())] = u
		}
		if u.GetEmail() != "" {
			byEmail[strings.ToLower(u.GetEmail())] = u
		}
	}

	var changes []*userV1.LdapSyncChange
	var warnings []string
	unchangedCount := int32(0)

	for i := range ldapUsers {
		ldapUser := &ldapUsers[i]
		var existing *userV1.User

		// Match by username first, then by email
		if ldapUser.Username != "" {
			existing = byUsername[strings.ToLower(ldapUser.Username)]
		}
		if existing == nil && ldapUser.Email != "" {
			existing = byEmail[strings.ToLower(ldapUser.Email)]
		}

		if existing == nil {
			// New user
			changes = append(changes, &userV1.LdapSyncChange{
				Action: userV1.LdapSyncChange_ACTION_CREATE,
				User:   ldapUserToProto(ldapUser),
				LdapDn: &ldapUser.DN,
			})
		} else {
			changedFields := computeChangedUserFields(existing, ldapUser)
			if len(changedFields) > 0 {
				changes = append(changes, &userV1.LdapSyncChange{
					Action:        userV1.LdapSyncChange_ACTION_UPDATE,
					User:          ldapUserToProto(ldapUser),
					ChangedFields: changedFields,
					ExistingId:    existing.Id,
					LdapDn:        &ldapUser.DN,
				})
			} else {
				unchangedCount++
			}
		}
	}

	newCount := int32(0)
	updateCount := int32(0)
	for _, c := range changes {
		switch c.Action {
		case userV1.LdapSyncChange_ACTION_CREATE:
			newCount++
		case userV1.LdapSyncChange_ACTION_UPDATE:
			updateCount++
		}
	}

	return &userV1.LdapSyncPreviewResponse{
		TotalLdapEntries: int32(len(ldapUsers)),
		NewCount:         newCount,
		UpdateCount:      updateCount,
		UnchangedCount:   unchangedCount,
		Changes:          changes,
		Warnings:         warnings,
	}, ldapUsers, nil
}
