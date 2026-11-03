# SupabaseAuthBundle

Stateless Symfony authentication via Supabase-issued JWTs.

The bundle verifies a Supabase JWT (signature against the project JWKS, plus the
`iss`, `exp`, `iat` and `nbf` claims, and `aud` when configured) and hands the
verified claims to an application-provided resolver that maps the Supabase
identity to your own user. Verification logic lives here once; the only
application glue is the resolver.

## Requirements

- PHP 8.3+ and Symfony 7.2+.
- A Supabase project using [asymmetric JWT signing keys](https://supabase.com/docs/guides/auth/signing-keys)
  (ES256 or RS256). A project still on the legacy shared secret publishes no keys,
  so every token answers `503`.
- For RS256, the `gmp` PHP extension, or `bcmath` as a slower alternative.
  Verifying a token takes under 1 ms with `gmp` and 5 to 20 ms with `bcmath`. With
  neither it costs about 400 ms of CPU on every request, or 18 s with older
  `brick/math` versions. The official `php` Docker images include neither. ES256
  needs neither.

## Installation

```bash
composer require kyzegs/supabase-auth-bundle
```

If you don't use Symfony Flex, register the bundle manually in
`config/bundles.php`:

```php
return [
    // ...
    Kyzegs\SupabaseAuthBundle\SupabaseAuthBundle::class => ['all' => true],
];
```

## Configuration

`config/packages/supabase_auth.yaml`:

```yaml
supabase_auth:
    url: '%env(SUPABASE_URL)%'   # required, absolute http(s) URL
    jwks_ttl: 600                # optional, JWKS cache TTL in seconds
    leeway: 0                    # optional, allowed clock skew in seconds
    audience: 'authenticated'    # optional, required `aud` claim value
    algorithms: ['RS256', 'ES256'] # optional, accepted signature algorithms

when@test:
    supabase_auth:
        test_mode: true          # accept "test-user-{id}" tokens instead of real JWTs
```

| Option              | Default          | Description                                                        |
|---------------------|------------------|--------------------------------------------------------------------|
| `url`               | _(required)_     | Supabase project URL, e.g. `https://xxxx.supabase.co`. Must be an absolute http(s) URL. |
| `jwks_ttl`          | `600`            | Seconds to cache the JWKS (matches the Supabase edge cache). Supabase advises against caching longer: a revoked key stays trusted until both this cache and its own 10-minute edge cache have expired. |
| `leeway`            | `0`              | Allowed clock skew (seconds) for the `exp`, `iat` and `nbf` checks. At `0`, a token used right after it was issued answers `401` if this server's clock runs behind Supabase's, so consider a few seconds in production. |
| `audience`          | `null`           | When set, the token must have an `aud` claim containing this value (Supabase uses `authenticated`). |
| `algorithms`        | `[RS256, ES256]` | Signature algorithms accepted from the JWKS. Must be a subset of `RS256`, `ES256`. |
| `test_mode`         | `false`          | Swap the handler for one accepting `{prefix}{identifier}` tokens. Must be a literal boolean, and is refused in the `prod` environment. |
| `test_token_prefix` | `test-user-`     | Bearer-token prefix recognised in test mode.                      |

Invalid configuration (an unsupported algorithm, a negative `jwks_ttl`/`leeway`,
`test_mode` from an `%env()%` value or in `prod`) fails fast at container compile
time. The `url` is validated at runtime instead,
so an `%env(SUPABASE_URL)%` value — which is unresolved during compilation — is
accepted; a non-http(s) URL fails on first token verification.

## Failure responses

| Cause | Response |
|-------|----------|
| The token is malformed, has an invalid signature, lacks `iss`, `exp` or `sub` (or `aud` when `audience` is set), or fails claim checks | `401` |
| The resolver returns `null` | `401` |
| The JWKS cannot be fetched (5 s timeout) or parsed, or holds no keys | `503` |
| `url` is empty or not an absolute http(s) URL, or no valid `algorithms` are configured | `503` |

A `503` is a `ServiceUnavailableHttpException` with a generic message and the
cause as its previous exception, so clients can tell it apart from a rejected
token, and Symfony logs it at critical level. These failures are not cached: once
the JWKS is available again, the next request succeeds.

To see why a token was rejected, look for `Authenticator failed.` at info level on
the `security` log channel. The logged exception's previous exception holds the
cause, which is never sent to the client. Production logging often drops that
level, so you may need to lower the channel's threshold to see it.

## Wiring the firewall

Point your firewall's access-token handler at the public service id
`supabase_auth.token_handler`:

```yaml
# config/packages/security.yaml
security:
    firewalls:
        api:
            stateless: true
            access_token:
                token_handler: supabase_auth.token_handler
```

## Provide a user resolver

Implement `SupabaseUserResolverInterface` to map verified claims (typically the
`sub` claim) to your security user, and alias the interface to it:

```php
namespace App\Security;

use App\Repository\UserRepositoryInterface;
use Kyzegs\SupabaseAuthBundle\Contract\SupabaseUserResolverInterface;
use Symfony\Component\Security\Core\User\UserInterface;

final class SupabaseUserResolver implements SupabaseUserResolverInterface
{
    public function __construct(private UserRepositoryInterface $users) {}

    public function resolve(array $claims): ?UserInterface
    {
        return $this->users->find($claims['sub']);
    }
}
```

```yaml
# config/services.yaml
services:
    Kyzegs\SupabaseAuthBundle\Contract\SupabaseUserResolverInterface: '@App\Security\SupabaseUserResolver'
```

Returning `null` from `resolve()` produces an authentication failure.

## Testing your application

With `test_mode: true`, send `Authorization: Bearer test-user-{identifier}` and
the bundle calls your resolver with `['sub' => '{identifier}']` — no real JWT
required.

Test mode lets any caller sign in as any user, so keep it under `when@test`. The
bundle refuses it in the `prod` environment, but cannot recognise a production
environment you named something else.

## License

MIT
