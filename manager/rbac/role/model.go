package role

import (
	"strings"

	"github.com/pkg/errors"
)

// Model represents the whole access control model.
type Model map[string]AssertionMap

// AssertionMap is the collection of assertions, can be "r", "p", "g", "e", "m".
type AssertionMap map[string]*Assertion

// Assertion represents an expression in a section of the model.
// For example: r = sub, obj, act
type Assertion struct {
	Key    string
	Value  string
	Tokens []string
	Rule   [][]string
	RM     *RoleManager
}

var sectionKVMap = map[string]string{
	"r": "sub, dom, obj, act",
	"p": "sub, dom, obj, act",
	"g": "_, _, _",
	"e": "some(where (p.eft == allow)) && !some(where (p.eft == deny))",
	"m": "g(r.sub, p.sub, r.dom) && r.dom == p.dom && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)",
}

// newModel creates a model.
func newModel() Model {
	m := make(Model)

	loadSection(m, "r")
	loadSection(m, "p")
	loadSection(m, "e")
	loadSection(m, "m")
	loadSection(m, "g")
	return m
}

func loadSection(model Model, sec string) {
	loadAssertion(model, sec, sec)
}

func loadAssertion(model Model, sec string, key string) bool {
	if value, ok := sectionKVMap[key]; ok {
		return model.addDef(sec, key, value)
	}

	panic(errors.Errorf("section[%s] not support", sec))
	return false
}

// addDef adds an assertion to the model.
func (model Model) addDef(sec string, key string, value string) bool {
	ast := Assertion{}
	ast.Key = key
	ast.Value = value

	if ast.Value == "" {
		return false
	}

	if sec == "r" || sec == "p" {
		ast.Tokens = strings.Split(ast.Value, ", ")
		for i := range ast.Tokens {
			ast.Tokens[i] = key + "_" + ast.Tokens[i]
		}
	} else {
		ast.Value = RemoveComments(EscapeAssertion(ast.Value))
	}

	_, ok := model[sec]
	if !ok {
		model[sec] = make(AssertionMap)
	}

	model[sec][key] = &ast
	return true
}

// Clear clears all current rule.
func (model Model) Clear() {
	for _, ast := range model["p"] {
		ast.Rule = nil
	}

	for _, ast := range model["g"] {
		ast.Rule = nil
	}
}

// GetRule gets all rules by sec and ptype.
func (model Model) GetRule(sec string, ptype string) [][]string {
	return model[sec][ptype].Rule
}

// GetFilteredRule gets rules based on field filters from a model.
func (model Model) GetFilteredRule(sec string, ptype string, fieldIndex int, fieldValues ...string) [][]string {
	res := [][]string{}

	for _, rule := range model[sec][ptype].Rule {
		matched := true
		for i, fieldValue := range fieldValues {
			if fieldValue != "" && rule[fieldIndex+i] != fieldValue {
				matched = false
				break
			}
		}

		if matched {
			res = append(res, rule)
		}
	}

	return res
}

// HasRule determines whether a model has the specified rule.
func (model Model) HasRule(sec string, ptype string, rule []string) bool {
	for _, r := range model[sec][ptype].Rule {
		if ArrayEquals(rule, r) {
			return true
		}
	}

	return false
}

// Add adds a rule to the model.
func (model Model) Add(sec string, ptype string, rule []string) bool {
	if !model.HasRule(sec, ptype, rule) {
		model[sec][ptype].Rule = append(model[sec][ptype].Rule, rule)
		return true
	}
	return false
}

// Remove removes a rule from the model.
func (model Model) Remove(sec string, ptype string, rule []string) bool {
	for i, r := range model[sec][ptype].Rule {
		if ArrayEquals(rule, r) {
			model[sec][ptype].Rule = append(model[sec][ptype].Rule[:i], model[sec][ptype].Rule[i+1:]...)
			return true
		}
	}

	return false
}

// RemoveFilteredRule removes rules based on field filters from the model.
func (model Model) RemoveFilteredRule(sec string, ptype string, fieldIndex int, fieldValues ...string) bool {
	tmp := [][]string{}
	res := false
	for _, rule := range model[sec][ptype].Rule {
		matched := true
		for i, fieldValue := range fieldValues {
			if fieldValue != "" && rule[fieldIndex+i] != fieldValue {
				matched = false
				break
			}
		}

		if matched {
			res = true
		} else {
			tmp = append(tmp, rule)
		}
	}

	model[sec][ptype].Rule = tmp
	return res
}

// GetValuesForFieldInRule gets all values for a field for all rules in a model, duplicated values are removed.
func (model Model) GetValuesForFieldInRule(sec string, ptype string, fieldIndex int) []string {
	values := []string{}

	for _, rule := range model[sec][ptype].Rule {
		values = append(values, rule[fieldIndex])
	}

	ArrayRemoveDuplicates(&values)
	// sort.Strings(values)

	return values
}

// buildRoleLinks initializes the roles in RBAC.
func (model Model) buildRoleLinks(rm *RoleManager) {
	for _, ast := range model["g"] {
		ast.buildRoleLinks(rm)
	}
}

func (ast *Assertion) buildRoleLinks(rm *RoleManager) {
	ast.RM = rm
	count := strings.Count(ast.Value, "_")
	for _, rule := range ast.Rule {
		if count < 2 {
			panic(errors.New("the number of \"_\" in role definition should be at least 2"))
		}
		if len(rule) < count {
			panic(errors.New("grouping policy elements do not meet role definition"))
		}

		if count == 2 {
			ast.RM.AddLink(rule[0], rule[1])
		} else if count == 3 {
			ast.RM.AddLink(rule[0], rule[1], rule[2])
		} else if count == 4 {
			ast.RM.AddLink(rule[0], rule[1], rule[2], rule[3])
		}
	}

	LogPrint("Role links for: " + ast.Key)
	ast.RM.PrintRoles()
}

// loadRuleLineToModel loads a text line as a rule to model.
func loadRuleLineToModel(line string, model Model) {
	if line == "" {
		return
	}

	if strings.HasPrefix(line, "#") {
		return
	}

	tokens := strings.Split(line, ", ")

	key := tokens[0]
	sec := key[:1]
	model[sec][key].Rule = append(model[sec][key].Rule, tokens[1:])
}
