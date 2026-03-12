package authz.introspection

import rego.v1

# Secure policies access: Returns an empty object when data.policies is missing
policies := data.policies if data.policies
else := {}

# defaults
default authorized := false
default authorized_project := ""
default authorized_pair := []

# Input safe values: if input.subjects or input.pairs is missing, an empty array is used
subjects := input.subjects if input.subjects
else := []

pairs := input.pairs if input.pairs
else := []

# Platform administrator role code
platform_admin_role := "platform:admin"

# Check if you are a platform administrator
is_platform_admin if {
	some s in subjects
	s == platform_admin_role
}

# Platform administrator bypasses authorization checks and allows all operations
authorized if is_platform_admin

# Determine whether any subject is authorized for any pair (non-platform administrator)
authorized if {
	some s in subjects
	some grant in policies[s]
	some p in pairs
	p.resource == grant.pattern
	p.action == grant.method
}

# Return all authorized (resource, action) pairs
# Platform administrators return all requested pairs, non-platform administrators return matching pairs
authorized_pair := pairs if is_platform_admin
else := [p |
	some s in subjects
	some grant in policies[s]
	some p in pairs
	p.resource == grant.pattern
	p.action == grant.method
]

# The project field is currently hard-coded as "api"
authorized_project := "api" if authorized
