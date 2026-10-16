Background

GraphQL is a query language for APIs developed by Facebook in 2012 and open-sourced in 2015. Unlike REST, which exposes multiple endpoints with fixed response structures, GraphQL exposes a single endpoint (typically /graphql) that accepts client-defined queries. The client controls which fields to fetch and how deep to traverse relationships — a design that creates a unique attack surface.

Key concepts for a pentester:

Query — read operation (analogous to SELECT)
Mutation — write operation (analogous to INSERT/UPDATE/DELETE)
Introspection — built-in self-documentation mechanism that reveals the entire API schema
Resolver — server-side function behind each field; where business logic (and vulnerabilities) live
