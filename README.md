# grantry

OAuth 2.1 authorization server building blocks for Rust web apps and MCP servers.

**Status: placeholder.** The crate name is reserved. The code is being extracted from FlowDrop (OAuth for MCP clients) and Fons (device authorization grant), and Scotty will adopt it.

Planned scope:

- grants, with scopes that only ever narrow the user's own permissions;
- audience-bound access tokens, and refresh tokens that rotate, with reuse detection;
- authorization code with PKCE, exact redirect matching (loopback ports excepted);
- client identification through Client ID Metadata Documents, with dynamic registration (RFC 7591) as fallback;
- authorization server and protected resource metadata (RFC 8414, RFC 9728);
- the device authorization grant (RFC 8628);
- storage, consent screens and user lookup provided by the host application through traits;
- optional axum routers.

## License

[MPL-2.0](LICENSE).
