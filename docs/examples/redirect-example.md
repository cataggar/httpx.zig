# Redirect Following Example

Demonstrates redirect policy configuration including enablement through `ClientPolicy`, `max_redirects`, `preserve_method`, `preserve_headers`, `allow_cross_origin`, and the `getRedirectMethod` logic.

## Demo Program

```zig
const default = httpx.RedirectPolicy{};
std.debug.print("  max_redirects:    {d}\n", .{default.max_redirects});

const embedding_owned = httpx.ClientPolicy.embeddingOwned();
// embedding_owned.redirect == .disabled

const strict = httpx.RedirectPolicy.strict();
// strict.preserve_method == true

const redirect_method = default.getRedirectMethod(301, .POST);
// 301 with POST -> method changes to GET

const strict_method = strict.getRedirectMethod(301, .POST);
// strict: 301 with POST -> POST preserved
```

## Run

```
zig build run-all-redirect_example
```

## Checklist

- [x] Managed client policy follows redirects, changing POST→GET for 301/302/303
- [x] `ClientPolicy.embeddingOwned()` disables following
- [x] `RedirectPolicy.strict()` preserves original HTTP method
- [x] 307/308 always preserve the method
- [x] 301/302 change POST to GET under default policy
- [x] 303 always changes to GET regardless of policy
