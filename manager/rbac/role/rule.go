package role

import (
	"reflect"
)

// RuleManager is the main interface for rule management.
type RuleManager struct {
	rules Model
	rm    *RoleManager

	autobuildRoleLinks bool
}

func newRuleManager(params ...interface{}) *RuleManager {
	return &RuleManager{
		rules:              newModel(),
		rm:                 newRoleManager(10),
		autobuildRoleLinks: true,
	}
}

// AddRoleForUserInDomain adds a role for a user inside a domain.
// Returns false if the user already has the role (aka not affected).
func (m *RuleManager) AddRoleForUserInDomain(user string, role string, domain string) bool {
	return m.addGroupingRule(user, role, domain)
}

// addGroupingRule adds a role inheritance rule to the current rule.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
func (m *RuleManager) addGroupingRule(params ...interface{}) bool {
	return m.addNamedGroupingRule("g", params...)
}

// addNamedGroupingRule adds a named role inheritance rule to the current rule.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
func (m *RuleManager) addNamedGroupingRule(ptype string, params ...interface{}) bool {
	ruleAdded := false
	if len(params) == 1 && reflect.TypeOf(params[0]).Kind() == reflect.Slice {
		ruleAdded = m.addRule("g", ptype, params[0].([]string))
	} else {
		rule := make([]string, 0)
		for _, param := range params {
			rule = append(rule, param.(string))
		}

		ruleAdded = m.addRule("g", ptype, rule)
	}

	if m.autobuildRoleLinks {
		m.buildRoleLinks()
	}
	return ruleAdded
}

// addRule adds a rule to the current rule.
func (m *RuleManager) addRule(sec string, ptype string, rule []string) bool {
	ruleAdded := m.rules.Add(sec, ptype, rule)

	/*
		if ruleAdded {
			if m.adapter != nil && m.autoSave {
				err := m.adapter.AddPolicy(sec, ptype, rule)
				if err != nil && err.Error() != "not implemented" {
					panic(err)
				} else if err == nil {
					if m.watcher != nil {
						m.watcher.Update()
					}
				}
			}
		}
	*/

	return ruleAdded
}

// DeleteUser deletes a user.
// Returns false if the user does not exist (aka not affected).
func (m *RuleManager) DeleteUser(user string) bool {
	return m.removeFilteredGroupingRule(0, user)
}

// DeleteRole deletes a role.
func (m *RuleManager) DeleteRole(role string) {
	m.removeFilteredGroupingRule(1, role)
	m.removeFilteredRules(0, role)
}

// removeFilteredGroupingRule removes a role inheritance rule from the current rule, field filters can be specified.
func (m *RuleManager) removeFilteredGroupingRule(fieldIndex int, fieldValues ...string) bool {
	return m.removeFilteredNamedGroupingRule("g", fieldIndex, fieldValues...)
}

// removeFilteredNamedGroupingRule removes a role inheritance rule from the current named rule, field filters can be specified.
func (m *RuleManager) removeFilteredNamedGroupingRule(ptype string, fieldIndex int, fieldValues ...string) bool {
	ruleRemoved := m.removeFilteredRule("g", ptype, fieldIndex, fieldValues...)
	if m.autobuildRoleLinks {
		m.buildRoleLinks()
	}
	return ruleRemoved
}

// removeFilteredRules removes an authorization rule from the current rule, field filters can be specified.
func (m *RuleManager) removeFilteredRules(fieldIndex int, fieldValues ...string) bool {
	return m.removeFilteredNamedRule("p", fieldIndex, fieldValues...)
}

// removeFilteredNamedRule removes an authorization rule from the current named rule, field filters can be specified.
func (m *RuleManager) removeFilteredNamedRule(ptype string, fieldIndex int, fieldValues ...string) bool {
	ruleRemoved := m.removeFilteredRule("p", ptype, fieldIndex, fieldValues...)
	return ruleRemoved
}

// removeFilteredRule removes rules based on field filters from the current rule.
func (m *RuleManager) removeFilteredRule(sec string, ptype string, fieldIndex int, fieldValues ...string) bool {
	ruleRemoved := m.rules.RemoveFilteredRule(sec, ptype, fieldIndex, fieldValues...)

	/*
		if ruleRemoved {
			if m.adapter != nil && m.autoSave {
				err := m.adapter.removeFilteredRules(sec, ptype, fieldIndex, fieldValues...)
				if err != nil && err.Error() != "not implemented" {
					panic(err)
				} else if err == nil {
					if m.watcher != nil {
						m.watcher.Update()
					}
				}
			}
		}
	*/

	return ruleRemoved
}

// GetRolesForUserInDomain gets the roles that a user has inside a domain.
func (m *RuleManager) GetRolesForUserInDomain(name string, domain string) []string {
	res, _ := m.rules["g"]["g"].RM.GetRoles(name, domain)
	return res
}

// GetRolesForUser gets the roles that a user has.
func (m *RuleManager) GetRolesForUser(name string) []string {
	res, _ := m.rules["g"]["g"].RM.GetRoles(name)
	return res
}

// GetUsersForRoleInDomain gets the users that has a role.
func (m *RuleManager) GetUsersForRoleInDomain(name, domain string) []string {
	res, _ := m.rules["g"]["g"].RM.GetUsers(name, domain)
	return res
}

// GetUsersForRole gets the users that has a role.
func (m *RuleManager) GetUsersForRole(name string) []string {
	res, _ := m.rules["g"]["g"].RM.GetUsers(name)
	return res
}

// HasRoleForUserInDomain determines whether a user has a role.
func (m *RuleManager) HasRoleForUserInDomain(name, domain string, role string) bool {
	roles := m.GetRolesForUser(name, domain)

	hasRole := false
	for _, r := range roles {
		if r == role {
			hasRole = true
			break
		}
	}

	return hasRole
}

// HasRoleForUser determines whether a user has a role.
func (m *RuleManager) HasRoleForUser(name string, role string) bool {
	roles := m.GetRolesForUser(name)

	hasRole := false
	for _, r := range roles {
		if r == role {
			hasRole = true
			break
		}
	}

	return hasRole
}

// GetAllRoles gets the list of roles that show up in the current rule.
func (m *RuleManager) GetAllRoles() []string {
	return m.getAllNamedRoles("g")
}

// getAllNamedRoles gets the list of roles that show up in the current named rule.
func (m *RuleManager) getAllNamedRoles(ptype string) []string {
	return m.rules.GetValuesForFieldInRule("g", ptype, 1)
}

// buildRoleLinks manually rebuild the role inheritance relations.
func (m *RuleManager) buildRoleLinks() {
	m.rm.Clear()
	m.rules.buildRoleLinks(m.rm)
}
