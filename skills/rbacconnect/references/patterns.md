# rbacconnect Common Patterns & Recipes

## Table of Contents

- [Basic Setup](#basic-setup)
- [Multi-Level Authorization](#multi-level-authorization)
- [Super-Roles](#super-roles)
- [Hot-Reloading from Database](#hot-reloading-from-database)
- [Custom Role Extractors](#custom-role-extractors)
- [Custom Error Factory](#custom-error-factory)
- [Testing Patterns](#testing-patterns)
- [Common Mistakes](#common-mistakes)

---

## Basic Setup

Minimal working configuration with fail-closed defaults:

```go
package main

import (
    "net/http"

    "connectrpc.com/connect"
    "github.com/sxwebdev/rbacconnect"
    userv1connect "gen/user/v1/userv1connect"
)

func main() {
    policy := rbacconnect.NewPolicyBuilder().
        WithDefaultAllow(false).
        When(rbacconnect.Svc("user.v1.UserService")).
            Allow("admin", "user").
        Build()

    provider := rbacconnect.NewProvider(policy)
    interceptor := rbacconnect.NewInterceptor(provider, rbacconnect.Options{})

    mux := http.NewServeMux()
    mux.Handle(userv1connect.NewUserServiceHandler(
        &userServer{},
        connect.WithInterceptors(interceptor),
    ))

    http.ListenAndServe(":8080", authMiddleware(mux))
}

func authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        user := authenticate(r) // your auth logic
        ctx := rbacconnect.WithRoles(r.Context(), user.Roles...)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

---

## Multi-Level Authorization

Use layered rules: broad access at package/service level, surgical restrictions at procedure level.

```go
policy := rbacconnect.NewPolicyBuilder().
    WithDefaultAllow(false).
    // Broad: all public API methods open to authenticated users
    When(rbacconnect.Pkg("public")).
        Allow("user", "admin").
    // Narrow: admin service restricted
    When(rbacconnect.Svc("admin.AdminService")).
        Allow("admin").
    // Surgical: even admins can't nuke without super-admin
    When(rbacconnect.Proc("/admin.AdminService/DeleteAllData")).
        Deny("admin").
        Allow("super_admin").
    Build()
```

Procedure rules always win over service rules, which win over package rules. This lets you
define broad policies and then carve out exceptions.

---

## Super-Roles

Super-roles bypass all rules entirely. Use for system accounts and emergency access:

```go
policy := rbacconnect.NewPolicyBuilder().
    WithSuperRoles("root", "system_service_account").
    WithDefaultAllow(false).
    // ... normal rules ...
    Build()
```

Super-role check happens first, before any rule evaluation. A user with a super-role is always
allowed regardless of Deny rules.

---

## Hot-Reloading from Database

Load policies from a database and refresh periodically:

```go
func startPolicyRefresh(ctx context.Context, provider *rbacconnect.Provider, db *sql.DB) {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            policy, err := buildPolicyFromDB(db)
            if err != nil {
                log.Printf("policy refresh failed: %v", err)
                continue // keep old policy on error
            }
            provider.Update(policy)
        }
    }
}

func buildPolicyFromDB(db *sql.DB) (*rbacconnect.Policy, error) {
    rows, err := db.Query("SELECT role, resource_type, resource, action FROM permissions")
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    builder := rbacconnect.NewPolicyBuilder().WithDefaultAllow(false)

    for rows.Next() {
        var role, resType, resource, action string
        if err := rows.Scan(&role, &resType, &resource, &action); err != nil {
            return nil, err
        }

        var sel rbacconnect.Selector
        switch resType {
        case "procedure":
            sel = rbacconnect.Proc(resource)
        case "service":
            sel = rbacconnect.Svc(resource)
        case "package":
            sel = rbacconnect.Pkg(resource)
        default:
            sel = rbacconnect.Any()
        }

        clause := builder.When(sel)
        switch action {
        case "allow":
            clause.Allow(role)
        case "deny":
            clause.Deny(role)
        }
    }

    return builder.Build(), rows.Err()
}
```

---

## Custom Role Extractors

### From JWT Claims

```go
interceptor := rbacconnect.NewInterceptor(provider, rbacconnect.Options{
    RoleExtractor: rbacconnect.RoleExtractorFunc(func(ctx context.Context) ([]rbacconnect.Role, error) {
        claims, ok := jwtClaimsFromContext(ctx)
        if !ok {
            return nil, errors.New("no JWT claims in context")
        }
        return claims.Roles, nil
    }),
})
```

### From gRPC Metadata

```go
RoleExtractor: rbacconnect.RoleExtractorFunc(func(ctx context.Context) ([]rbacconnect.Role, error) {
    md, ok := metadata.FromIncomingContext(ctx)
    if !ok {
        return nil, errors.New("no metadata")
    }
    roles := md.Get("x-user-roles")
    if len(roles) == 0 {
        return nil, errors.New("no roles in metadata")
    }
    return roles, nil
})
```

### From Connect Headers

```go
// In an earlier interceptor, extract roles from headers:
RoleExtractor: rbacconnect.RoleExtractorFunc(func(ctx context.Context) ([]rbacconnect.Role, error) {
    header := connect.RequestFromContext(ctx)
    if header == nil {
        return nil, errors.New("no request in context")
    }
    rolesStr := header.Header().Get("X-User-Roles")
    if rolesStr == "" {
        return nil, errors.New("no roles header")
    }
    return strings.Split(rolesStr, ","), nil
})
```

---

## Custom Error Factory

Customize error responses (e.g., add error details or metadata):

```go
interceptor := rbacconnect.NewInterceptor(provider, rbacconnect.Options{
    ErrorFactory: func(code connect.Code, msg string) *connect.Error {
        err := connect.NewError(code, errors.New(msg))
        // Add structured error details
        detail, _ := connect.NewErrorDetail(&errdetails.ErrorInfo{
            Reason: "RBAC_DENIED",
            Domain: "myapp.example.com",
        })
        if detail != nil {
            err.AddDetail(detail)
        }
        return err
    },
})
```

---

## Testing Patterns

### Unit Testing Policies

Test policies directly without the interceptor:

```go
func TestAdminPolicy(t *testing.T) {
    policy := rbacconnect.NewPolicyBuilder().
        WithDefaultAllow(false).
        When(rbacconnect.Svc("api.AdminService")).Allow("admin").
        Build()

    tests := []struct {
        name      string
        procedure string
        service   string
        pkg       string
        roles     []string
        wantAllow bool
    }{
        {
            name:      "admin allowed",
            procedure: "/api.AdminService/DoThing",
            service:   "api.AdminService",
            pkg:       "api",
            roles:     []string{"admin"},
            wantAllow: true,
        },
        {
            name:      "user denied",
            procedure: "/api.AdminService/DoThing",
            service:   "api.AdminService",
            pkg:       "api",
            roles:     []string{"user"},
            wantAllow: false,
        },
        {
            name:      "no roles denied",
            procedure: "/api.AdminService/DoThing",
            service:   "api.AdminService",
            pkg:       "api",
            roles:     nil,
            wantAllow: false,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            d := policy.Evaluate(tt.procedure, tt.service, tt.pkg, tt.roles)
            if d.Allowed != tt.wantAllow {
                t.Errorf("got Allowed=%v, want %v (reason: %s)", d.Allowed, tt.wantAllow, d.Reason)
            }
        })
    }
}
```

### Testing with SplitProc

Use `SplitProc` to avoid manually specifying service and package in tests:

```go
proc := "/api.UserService/GetUser"
svc, pkg := rbacconnect.SplitProc(proc)
d := policy.Evaluate(proc, svc, pkg, []string{"user"})
```

### Testing Decision Details

Verify not just allowed/denied, but which rule matched:

```go
d := policy.Evaluate("/api.Svc/Method", "api.Svc", "api", []string{"admin"})
assert.True(t, d.Allowed)
assert.Equal(t, "service", d.Selector)  // matched at service level
assert.Equal(t, "api.Svc", d.Matched)   // matched this service
```

---

## Common Mistakes

### Forgetting WithDefaultAllow(false)

The builder defaults to `false`, but be explicit about it for clarity and safety:

```go
// Good: explicit fail-closed
rbacconnect.NewPolicyBuilder().WithDefaultAllow(false)

// Risky: relying on implicit default
rbacconnect.NewPolicyBuilder()
```

### Setting Roles After the Interceptor

Roles must be in the context BEFORE the interceptor runs. Place auth middleware before
the connect handler, not after:

```go
// Correct: middleware wraps mux, so roles are set before interceptor
http.ListenAndServe(":8080", authMiddleware(mux))

// Wrong: roles never reach the interceptor
```

### Expecting Deny to Override Super-Roles

Super-roles bypass ALL rules, including Deny. If you need to restrict a super-role,
remove it from the super-roles list and use regular rules instead.

### Using Allow Where Deny Is Needed

If a role should have broad access with one exception, use Deny at the specific level:

```go
// Good: broad allow, surgical deny
When(Svc("api.UserService")).Allow("manager").
When(Proc("/api.UserService/DeleteUser")).Deny("manager")

// Bad: trying to enumerate all allowed procedures
When(Proc("/api.UserService/GetUser")).Allow("manager").
When(Proc("/api.UserService/ListUsers")).Allow("manager")
// ... easy to miss new methods
```
