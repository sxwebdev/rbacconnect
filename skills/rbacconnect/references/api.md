# rbacconnect API Reference

## Table of Contents

- [Types](#types)
- [Selector Constructors](#selector-constructors)
- [PolicyBuilder](#policybuilder)
- [Policy](#policy)
- [Provider](#provider)
- [Interceptor](#interceptor)
- [Context Helpers](#context-helpers)
- [Role Extraction](#role-extraction)
- [Batch Helpers](#batch-helpers)
- [Utilities](#utilities)

---

## Types

### Role

```go
type Role = string
```

String alias for role names.

### RoleSet

```go
type RoleSet map[Role]struct{}
```

Map-based set for O(1) role membership checks.

```go
func NewRoleSet(roles ...Role) RoleSet
```

Creates a RoleSet from a list of role strings.

### Selector

```go
type Selector struct {
    Procedure string // "/pkg.Service/Method"
    Service   string // "pkg.Service"
    Package   string // "pkg"
    Default   bool   // true for Any() selector
}
```

Defines the scope of a rule. Exactly one field should be set.

### Rule

```go
type Rule struct {
    Allow RoleSet
    Deny  RoleSet
}
```

Holds Allow and Deny role sets for a given selector.

### Decision

```go
type Decision struct {
    Allowed  bool   // Whether access was granted
    Selector string // Level that matched: "super", "procedure", "service", "package", "default", "fallback"
    Matched  string // The specific pattern matched (e.g. "/api.Svc/Method")
    Reason   string // Human-readable explanation
}
```

Returned by `Policy.Evaluate()`. Provides full audit trail for authorization decisions.

### Options

```go
type Options struct {
    RoleExtractor RoleExtractor
    SpecSplitter  func(connect.Spec) (procedure, service, pkg string)
    ErrorFactory  func(code connect.Code, msg string) *connect.Error
}
```

Configuration for the Interceptor. All fields are optional with sensible defaults:

- `RoleExtractor`: defaults to reading roles from context via `RolesFromContext()`
- `SpecSplitter`: defaults to parsing `/pkg.Service/Method` format
- `ErrorFactory`: defaults to `connect.NewError(code, errors.New(msg))`

---

## Selector Constructors

```go
func Proc(procedure string) Selector  // Procedure-level: "/pkg.Service/Method"
func Svc(service string) Selector     // Service-level: "pkg.Service"
func Pkg(pkg string) Selector         // Package-level: "pkg"
func Any() Selector                   // Default rule (matches everything)
```

Each returns a Selector with the appropriate field set. Use these with `PolicyBuilder.When()`.

**Format conventions:**

- Procedures include the leading slash: `"/api.UserService/GetUser"`
- Services use dot notation: `"api.UserService"`
- Packages are the protobuf package name: `"api"`

---

## PolicyBuilder

### Constructor

```go
func NewPolicyBuilder() *PolicyBuilder
```

Creates an empty builder with `defaultAllow: false`.

### Methods

```go
func (b *PolicyBuilder) WithSuperRoles(roles ...Role) *PolicyBuilder
```

Adds roles that bypass all rules. Returns builder for chaining.

```go
func (b *PolicyBuilder) WithDefaultAllow(allow bool) *PolicyBuilder
```

Sets the fallback behavior when no rule matches. Returns builder for chaining.

```go
func (b *PolicyBuilder) When(sel Selector) *clause
```

Starts a new rule for the given selector. Returns a `clause` for chaining Allow/Deny.

```go
func (b *PolicyBuilder) Build() *Policy
```

Finalizes and returns an immutable Policy.

### Clause Methods

The `clause` type is returned by `When()` and provides:

```go
func (c *clause) Allow(roles ...Role) *clause  // Add roles to Allow set
func (c *clause) Deny(roles ...Role) *clause   // Add roles to Deny set
func (c *clause) When(sel Selector) *clause     // Start new rule (chains back to builder)
```

All return `*clause` for fluent chaining.

---

## Policy

### Methods

```go
func (p *Policy) Evaluate(procedure, service, pkg string, roles []Role) Decision
```

Pure function. Checks authorization by walking the specificity chain:
Super > Procedure > Service > Package > Default > Fallback.

Returns a Decision with full audit information.

---

## Provider

Thread-safe atomic policy holder for hot-reloading.

### Constructor

```go
func NewProvider(p *Policy) *Provider
```

Creates a Provider with an initial policy.

### Methods

```go
func (p *Provider) Get() *Policy      // Atomic load of current policy
func (p *Provider) Update(newP *Policy) // Atomic store of new policy
```

Uses `sync/atomic.Pointer[Policy]` internally — lock-free and safe for concurrent access.

---

## Interceptor

Implements `connect.Interceptor` for authorization enforcement.

### Constructor

```go
func NewInterceptor(provider *Provider, opts Options) *Interceptor
```

Creates an interceptor that reads policy from the provider on each request.

### Methods (connect.Interceptor interface)

```go
func (i *Interceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc
func (i *Interceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc
func (i *Interceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc
```

- `WrapUnary` and `WrapStreamingHandler` enforce RBAC on server-side calls
- `WrapStreamingClient` is a pass-through (no client-side enforcement)

**Authorization flow:**

1. Extract roles via RoleExtractor
2. Parse procedure/service/package from connect.Spec
3. Load current policy from Provider
4. Call policy.Evaluate()
5. If denied: return PermissionDenied (or Unauthenticated if no roles found)
6. If allowed: call next handler

---

## Context Helpers

```go
func WithRoles(ctx context.Context, roles ...Role) context.Context
```

Stores roles in context. Use in authentication middleware before the interceptor runs.

```go
func RolesFromContext(ctx context.Context) ([]Role, bool)
```

Retrieves roles from context. Returns `(nil, false)` if no roles are set.

---

## Role Extraction

### Interface

```go
type RoleExtractor interface {
    ExtractRoles(ctx context.Context) ([]Role, error)
}
```

### Function Adapter

```go
type RoleExtractorFunc func(ctx context.Context) ([]Role, error)
```

Implements `RoleExtractor` so standalone functions can be used directly:

```go
rbacconnect.Options{
    RoleExtractor: rbacconnect.RoleExtractorFunc(func(ctx context.Context) ([]rbacconnect.Role, error) {
        return extractFromJWT(ctx)
    }),
}
```

---

## Batch Helpers

Convenience functions for adding the same role to multiple selectors at once:

```go
func AllowProcs(b *PolicyBuilder, role Role, procs ...string)
func DenyProcs(b *PolicyBuilder, role Role, procs ...string)
func AllowServices(b *PolicyBuilder, role Role, services ...string)
func DenyServices(b *PolicyBuilder, role Role, services ...string)
func AllowPackages(b *PolicyBuilder, role Role, packages ...string)
func DenyPackages(b *PolicyBuilder, role Role, packages ...string)
```

Each calls `b.When(selector).Allow/Deny(role)` for every item in the variadic list.

---

## Utilities

```go
func SplitProc(proc string) (service, pkg string)
```

Parses a procedure string like `"/api.UserService/GetUser"` into:

- service: `"api.UserService"`
- pkg: `"api"`

Used internally by the default SpecSplitter. Useful for custom splitters or testing.
