<?php

declare(strict_types=1);

namespace Kyzegs\SupabaseAuthBundle\Security;

use Kyzegs\SupabaseAuthBundle\Contract\SupabaseUserResolverInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\AccessToken\AccessTokenHandlerInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;

/**
 * Test-only token handler. Accepts a bearer token of the form
 * "{prefix}{identifier}" (default prefix "test-user-") and resolves the user
 * by passing the identifier as the `sub` claim to the user resolver.
 *
 * Enable via the bundle's `test_mode` option so functional tests can
 * authenticate without minting real Supabase JWTs. It lets any caller sign in as
 * any user, which is why the bundle refuses that option in the "prod" environment.
 */
final class TestAccessTokenHandler implements AccessTokenHandlerInterface
{
    public function __construct(
        private SupabaseUserResolverInterface $userResolver,
        private string $prefix = 'test-user-',
    ) {
    }

    public function getUserBadgeFrom(#[\SensitiveParameter] string $accessToken): UserBadge
    {
        if (!str_starts_with($accessToken, $this->prefix)) {
            throw new AuthenticationException('Invalid token.');
        }

        $identifier = substr($accessToken, strlen($this->prefix));

        $user = $this->userResolver->resolve(['sub' => $identifier]);

        if (null === $user) {
            throw new AuthenticationException('User not found.');
        }

        return new UserBadge($user->getUserIdentifier(), fn () => $user);
    }
}
