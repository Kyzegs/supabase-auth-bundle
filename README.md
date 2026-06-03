# SupabaseAuthBundle

Stateless Symfony authentication via Supabase-issued JWTs.

The bundle verifies a Supabase JWT (signature against the project JWKS, plus
`exp` and `iss` checks) and hands the verified claims to an application-provided
resolver that maps the Supabase identity to your own user. Verification logic
lives here once; the only application glue is the resolver.

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
    url: '%env(SUPABASE_URL)%'   # required, absolute http(s) URL, no trailing slash
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
| `jwks_ttl`          | `600`            | Seconds to cache the JWKS (matches the Supabase edge cache).      |
| `leeway`            | `0`              | Allowed clock skew (seconds) for the `exp`, `iat` and `nbf` checks. |
| `audience`          | `null`           | When set, the token `aud` claim must contain this value (Supabase uses `authenticated`). |
| `algorithms`        | `[RS256, ES256]` | Signature algorithms accepted from the JWKS. Must be a subset of `RS256`, `ES256`. |
| `test_mode`         | `false`          | Swap the handler for one accepting `{prefix}{identifier}` tokens. |
| `test_token_prefix` | `test-user-`     | Bearer-token prefix recognised in test mode.                      |

Invalid configuration (an unsupported algorithm, a negative `jwks_ttl`/`leeway`)
fails fast at container compile time. The `url` is validated at runtime instead,
so an `%env(SUPABASE_URL)%` value — which is unresolved during compilation — is
accepted; a non-http(s) URL is rejected on first token verification.

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

## License

MIT
