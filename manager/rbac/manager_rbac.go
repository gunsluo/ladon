package rbac

import (
	"github.com/ory/ladon"
	"github.com/ory/ladon/manager/memory"
)

// RbacManager is base on rbac manage, an persistent(pre loading in-memory) implementation of Manager.
type RbacManager struct {
	memory *memory.MemoryManager
}

// NewRbacManager constructs and initializes new RbacManager with no policies.
func NewRbacManager() *RbacManager {
	return &RbacManager{
		memory: memory.NewMemoryManager(),
	}
}

// Update updates an existing policy.
func (m *RbacManager) Update(policy ladon.Policy) error {
	return m.memory.Update(policy)
}

// GetAll returns all policies.
func (m *RbacManager) GetAll(limit, offset int64) (ladon.Policies, error) {
	return m.memory.GetAll(limit, offset)
}

// Create a new pollicy to RbacManager.
func (m *RbacManager) Create(policy ladon.Policy) error {
	return m.memory.Create(policy)
}

// Get retrieves a policy.
func (m *RbacManager) Get(id string) (ladon.Policy, error) {
	return m.memory.Get(id)
}

// Delete removes a policy.
func (m *RbacManager) Delete(id string) error {
	return m.Delete(id)
}

// FindRequestCandidates returns candidates that could match the request object. It either returns
// a set that exactly matches the request, or a superset of it. If an error occurs, it returns nil and
// the error.
func (m *RbacManager) FindRequestCandidates(r *ladon.Request) (ladon.Policies, error) {
	return m.FindRequestCandidates(r)
}
