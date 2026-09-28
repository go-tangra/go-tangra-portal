# Contract: framework edge `FrameSources` (go-tangra v4.2.2)

```go
type Config struct {
    // ...
    // FrameSources are additional origins the served pages may frame
    // (https://host[:port]); empty keeps frame-src at default-src 'self'.
    FrameSources []string
}
```

- `NewServer` refuses an entry that is not `https://host[:port]` (no path
  other than empty, no query, fragment or user info) or that contains
  whitespace, `;`, `,` or `'`: error `edge: frame source "<v>": …`.
- Empty/nil: the Content-Security-Policy is byte-for-byte the v4.2.1 policy.
- Non-empty: `; frame-src 'self' <o1> <o2>…` is inserted after
  `connect-src 'self'` (before `frame-ancestors 'none'`); trailing `/` is
  trimmed; `CSPExtra` still appended last.
- No other header changes (`X-Frame-Options: DENY`, `frame-ancestors 'none'`,
  COOP/CORP `same-origin` remain).

Gateway mapping: `edge.frame_sources` (YAML) + `console.public_origin` when
the console is enabled.
