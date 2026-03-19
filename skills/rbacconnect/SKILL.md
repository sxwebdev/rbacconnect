---
name: rbacconnect
description: >-
  Go RBAC authorization library for ConnectRPC (connect-go) services. Use this skill whenever
  working in the rbacconnect codebase — editing policies, interceptors, role extraction, context
  helpers, or tests. Also triggers when code imports "rbacconnect" or references PolicyBuilder,
  Provider, Interceptor, RoleExtractor, WithRoles, RolesFromContext, Proc/Svc/Pkg/Any selectors,
  or Decision types. Applies when the user mentions RBAC + connect-go, role-based access control
  for gRPC/ConnectRPC, policy hot-reloading, deny-over-allow rules, super-roles, or connect-go
  interceptor authorization.
user-invocable: false
---

# rbacconnect — RBAC for ConnectRPC

## Overview

rbacconnect is a declarative, thread-safe Role-Based Access Control library for connect-go RPC
services. It uses a fluent builder API to define policies with multi-level rule specificity
(Procedure > Service > Package > Default), atomic hot-reload via Provider, and a connect-go
Interceptor that enforces authorization on every RPC call.

Key design principles:

- **Deny over Allow** — within any rule level, Deny always wins
- **Most-specific wins** — Procedure rules override Service, which override Package, which override Default
- **Fail-closed** — default behavior is deny-all unless explicitly configured otherwise
- **Super-roles** — designated roles bypass all rules entirely
- **Immutable policies** — Build() produces a frozen policy; updates go through Provider.Update()

## Instructions

### Building a Policy

Use the fluent builder API. Every policy starts with `NewPolicyBuilder()` and ends with `.Build()`.

```go
policy := rbacconnect.NewPolicyBuilder().
    WithSuperRoles("root").
    WithDefaultAllow(false).
    When(rbacconnect.Proc("/api.UserService/GetUser")).
        Allow("admin", "user").
    When(rbacconnect.Svc("api.AdminService")).
        Allow("admin").
        Deny("guest").
    When(rbacconnect.Pkg("public")).
        Allow("guest", "user", "admin").
    When(rbacconnect.Any()).
        Allow("admin").
    Build()
```

Selector constructors and their format:

- `Proc("/package.Service/Method")` — exact procedure match (highest priority)
- `Svc("package.Service")` — all methods on a service
- `Pkg("package")` — all services in a package
- `Any()` — default rule (lowest priority, before fallback)

Chain `.Allow(roles...)` and `.Deny(roles...)` on the same selector. Use `.When()` to start a new rule.

For bulk rules, use batch helpers instead of repeating `.When()`:

```go
rbacconnect.AllowProcs(builder, "user", "/api.Svc/A", "/api.Svc/B", "/api.Svc/C")
rbacconnect.DenyServices(builder, "guest", "api.AdminService", "api.InternalService")
```

### Wiring the Interceptor

1. Create a Provider to hold the policy (enables hot-reload):

```go
provider := rbacconnect.NewProvider(policy)
```

2. Create the Interceptor:

```go
interceptor := rbacconnect.NewInterceptor(provider, rbacconnect.Options{})
```

3. Attach to connect-go handlers:

```go
mux.Handle(userv1connect.NewUserServiceHandler(
    &userServer{},
    connect.WithInterceptors(interceptor),
))
```

### Role Extraction

The default RoleExtractor reads roles from context via `RolesFromContext()`. Set roles in
authentication middleware:

```go
func authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        user := authenticate(r)
        ctx := rbacconnect.WithRoles(r.Context(), user.Roles...)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

For custom extraction (JWT, headers, database), provide a `RoleExtractor` in Options:

```go
interceptor := rbacconnect.NewInterceptor(provider, rbacconnect.Options{
    RoleExtractor: rbacconnect.RoleExtractorFunc(func(ctx context.Context) ([]rbacconnect.Role, error) {
        claims := jwtFromContext(ctx)
        return claims.Roles, nil
    }),
})
```

### Hot-Reloading Policies

Update policies at runtime without restarting the service. The Provider uses `atomic.Pointer`
for lock-free, thread-safe updates:

```go
newPolicy := rbacconnect.NewPolicyBuilder().
    WithSuperRoles("root", "admin").
    WithDefaultAllow(false).
    When(rbacconnect.Any()).Allow("admin").
    Build()

provider.Update(newPolicy) // Immediately visible to all interceptors
```

### Testing Policies

Test authorization logic directly on the Policy object without spinning up a server:

```go
decision := policy.Evaluate(
    "/api.UserService/GetUser", // procedure
    "api.UserService",          // service
    "api",                      // package
    []string{"user"},           // roles
)
assert.True(t, decision.Allowed)
assert.Equal(t, "procedure", decision.Selector)
```

The Decision struct provides full audit info: `Allowed`, `Selector` (which level matched),
`Matched` (what pattern matched), and `Reason` (human-readable explanation).

### Evaluation Order

Understand this order because it determines which rule wins:

1. **Super-roles** — if user has any super-role, always allowed (short-circuit)
2. **Procedure** — exact `/pkg.Service/Method` match
3. **Service** — `pkg.Service` match
4. **Package** — `pkg` match
5. **Default rule** — `When(Any())` rule
6. **Fallback** — `WithDefaultAllow()` value (defaults to false)

Within each level: if any user role is in Deny set, denied. Else if any role is in Allow set, allowed. Else no match at this level, fall through.

## Domain Reference

- Full API surface (types, functions, methods): see [references/api.md](references/api.md)
- Common patterns and recipes: see [references/patterns.md](references/patterns.md)

## Example

**Input:** User asks "Add RBAC so only admins can access the billing service, but all authenticated users can read invoices"

**Output:** Claude produces:

```go
policy := rbacconnect.NewPolicyBuilder().
    WithDefaultAllow(false).
    // All billing service methods restricted to admin
    When(rbacconnect.Svc("billing.BillingService")).
        Allow("admin").
    // Exception: any authenticated user can read invoices
    When(rbacconnect.Proc("/billing.BillingService/ListInvoices")).
        Allow("admin", "user").
    When(rbacconnect.Proc("/billing.BillingService/GetInvoice")).
        Allow("admin", "user").
    Build()

provider := rbacconnect.NewProvider(policy)
interceptor := rbacconnect.NewInterceptor(provider, rbacconnect.Options{})
```

Plus a test:

```go
func TestBillingPolicy(t *testing.T) {
    // Admin can access any billing method
    d := policy.Evaluate("/billing.BillingService/CreateCharge", "billing.BillingService", "billing", []string{"admin"})
    assert.True(t, d.Allowed)

    // Regular user cannot create charges
    d = policy.Evaluate("/billing.BillingService/CreateCharge", "billing.BillingService", "billing", []string{"user"})
    assert.False(t, d.Allowed)

    // Regular user can list invoices
    d = policy.Evaluate("/billing.BillingService/ListInvoices", "billing.BillingService", "billing", []string{"user"})
    assert.True(t, d.Allowed)
}
```

## Key Principles

- **Fail-closed by default.** Always use `WithDefaultAllow(false)` unless there is a specific reason not to. An open-by-default policy risks exposing new endpoints that haven't been explicitly protected.
- **Procedure rules for exceptions, service/package rules for broad access.** Define broad access at the service or package level, then use procedure-level rules to grant or restrict specific methods. This keeps policies readable and maintainable.
- **Deny is a scalpel, not a hammer.** Use Deny to carve out exceptions from broad Allow rules. If you find yourself writing many Deny rules, reconsider the policy structure — it may be simpler to restrict at a higher level and Allow specific methods.
- **Test policies in isolation.** Use `policy.Evaluate()` directly in unit tests. This is faster and more precise than integration tests through the interceptor.
- **Hot-reload for dynamic environments.** When roles or permissions come from a database or config service, use Provider.Update() to push new policies without downtime.
