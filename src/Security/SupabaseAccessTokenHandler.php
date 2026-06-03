<?php

declare(strict_types=1);

namespace Kyzegs\SupabaseAuthBundle\Security;

use Kyzegs\SupabaseAuthBundle\Contract\SupabaseJwtVerifierInterface;
use Kyzegs\SupabaseAuthBundle\Contract\SupabaseUserResolverInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\AccessToken\AccessTokenHandlerInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;

/**
 * Authenticates requests with a Supabase-issued JWT bearer token.
 *
 * Verifies the token, then delegates the identity → user lookup to the
 * application-provided {@see SupabaseUserResolverInterface}.
 */
final class SupabaseAccessTokenHandler implements AccessTokenHandlerInterface
{
    public function __construct(
        private SupabaseJwtVerifierInterface $verifier,
        private SupabaseUserResolverInterface $userResolver,
    ) {
    }

    public function getUserBadgeFrom(#[\SensitiveParameter] string $accessToken): UserBadge
    {
        try {
            $claims = $this->verifier->verify($accessToken);
        } catch (\Throwable $e) {
            throw new AuthenticationException('Invalid token.');
        }

        $user = $this->userResolver->resolve($claims);

        if (null === $user) {
            throw new AuthenticationException('User not found.');
        }

        return new UserBadge($user->getUserIdentifier(), fn () => $user);
    }
}
