package main

import (
	"fmt"
	"log"

	"github.com/gunsluo/ladon/manager/rbac/store"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/ory/ladon"
	"github.com/ory/ladon/manager/memory"
)

// A bunch of exemplary policies
var pols = []ladon.Policy{
	&ladon.DefaultPolicy{
		ID: "r:reach",
		Description: `This policy allows reach user to create, delete and get the listed resources,
			but only if the client ip matches and the request states that they are the owner of those resources as well.`,
		Subjects:  []string{"reach", "luoji", "peter", "<zac|ken>"},
		Resources: []string{"target.com;reach;reach.domain.com:resource:123", "target.com;cadre;cadre.domain.com:resource:345", "other.com;other;something:foo:<.+>"},
		Actions:   []string{"<create|delete>", "get"},
		Effect:    ladon.AllowAccess,
		Conditions: ladon.Conditions{
			"owner": &ladon.EqualsSubjectCondition{},
			"clientIP": &ladon.CIDRCondition{
				CIDR: "127.0.0.1/32",
			},
		},
	},
	&ladon.DefaultPolicy{
		ID:          "u:luoji",
		Description: `This policy allows luoji to update any resources`,
		Subjects:    []string{"luoji"},
		Actions:     []string{"update"},
		Resources:   []string{"<.*>"},
		Effect:      ladon.AllowAccess,
	},
}

// Some test cases
var cases = []struct {
	description   string
	accessRequest *ladon.Request
	expectErr     bool
}{
	{
		description: "should pass because policy 1 is matching and has effect allow.",
		accessRequest: &ladon.Request{
			Subject:  "reach",
			Action:   "create",
			Resource: "target.com;reach;reach.domain.com:resource:123",
			Context: ladon.Context{
				"owner":    "reach",
				"clientIP": "127.0.0.1",
			},
		},
		expectErr: true,
	},
	{
		description: "should pass because policy 1 is matching and has effect allow.",
		accessRequest: &ladon.Request{
			Subject:  "luoji",
			Action:   "create",
			Resource: "target.com;reach;reach.domain.com:resource:123",
			Context: ladon.Context{
				"owner":    "luoji",
				"clientIP": "127.0.0.1",
			},
		},
		expectErr: true,
	},
	{
		description: "should pass because policy 1 is matching and has effect allow.",
		accessRequest: &ladon.Request{
			Subject:  "luoji",
			Action:   "update",
			Resource: "target.com;reach;reach.domain.com:resource:345",
			Context: ladon.Context{
				"owner":    "luoji",
				"clientIP": "127.0.0.1",
			},
		},
		expectErr: true,
	},
	{
		description: "should fail because no policy is matching as the owner of the resource 345 is peter!",
		accessRequest: &ladon.Request{
			Subject:  "peter",
			Action:   "update",
			Resource: "target.com;reach;reach.domain.com:resource:345",
			Context: ladon.Context{
				"owner":    "peter",
				"clientIP": "127.0.0.1",
			},
		},
		expectErr: true,
	},
}

func main() {
	// The database manager expects a sqlx.DB object
	db, err := sqlx.Open("postgres", "user=root password=root host=127.0.0.1 port=5432 dbname=ladon sslmode=disable") // Your driver and data source.
	if err != nil {
		log.Fatalf("Could not connect to database: %s", err)
	}

	// You must call SQLManager.CreateSchemas(schema, table) before use
	manager := store.NewStoreManager(db, nil)
	n, err := manager.CreateSchemas("", "")
	if err != nil {
		log.Fatalf("Failed to create schemas: %s", err)
	}
	log.Printf("applied %d migrations", n)

	// Instantiate ladon with the default in-memory store.
	warden := &ladon.Ladon{
		Manager: memory.NewMemoryManager(),
	}

	// Add the policies defined above to the memory manager.
	for _, pol := range pols {
		err := warden.Manager.Create(pol)
		if err != nil {
			panic(err)
		}
	}

	for k, c := range cases {
		err := warden.IsAllowed(c.accessRequest)
		if err != nil {
			fmt.Printf("case=%d-%s   :%s\n", k, c.description, err)
		} else {
			fmt.Printf("case=%d-%s   :success\n", k, c.description)
		}
	}
}
