package role

import (
	"fmt"
	"testing"
)

func TestRuleManager(t *testing.T) {
	rm := newRuleManager()
	rm.AddRoleForUserInDomain("Bruce Lee", "master", "Kung Fu")
	rm.AddRoleForUserInDomain("YIP Man", "master", "Kung Fu")
	rm.AddRoleForUserInDomain("Peter", "fan", "Kung Fu")
	rm.AddRoleForUserInDomain("Tom", "fan", "Kung Fu")

	var roles []string
	roles = rm.GetRolesForUserInDomain("Bruce Lee", "Kung Fu")
	if roles == nil || len(roles) == 0 {
		t.Fatalf("GetRolesForUserInDomain failed")
		return
	}

	var users []string
	users = rm.GetUsersForRoleInDomain("master", "Kung Fu")
	if users == nil || len(users) == 0 {
		t.Fatalf("GetUsersForRoleInDomain failed")
		return
	}

	fmt.Println("=====>", users)
}
