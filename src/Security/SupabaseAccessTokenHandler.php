<?php

declare(strict_types=1);

namespace Kyzegs\SupabaseAuthBundle\Security;

use Kyzegs\SupabaseAuthBundle\Contract\SupabaseJwtVerifierInterface;
use Kyzegs\SupabaseAuthBundle\Contract\SupabaseUserResolverInterface;
use Kyzegs\SupabaseAuthBundle\Exception\VerificationUnavailableException;
use Symfony\Component\HttpKernel\Exception\ServiceUnavailableHttpException;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\AccessToken\AccessTokenHandlerInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;

/**
 * Authenticates requests with a Supabase-issued JWT bearer token.
 *
 * Verifies the token, then delegates the identity → user lookup to the
 * application-provided {@see SupabaseUserResolverInterface}. A token that fails
 * verification answers 401; a server that cannot verify any token answers 503.
 */
final class SupabaseAccessTokenHandler implements AccessTokenHandlerInterface
{
    public function __construct(
        private SupabaseJwtVerifierInterface $verifier,
        private SupabaseUserResolverInterface $userResolver,
    ) {
    }

    /**
     * @throws AuthenticationException         When the token is rejected or its user is not found
     * @throws ServiceUnavailableHttpException When the server cannot verify the token
     */
    public function getUserBadgeFrom(#[\SensitiveParameter] string $accessToken): UserBadge
    {
        try {
            $claims = $this->verifier->verify($accessToken);
        } catch (VerificationUnavailableException $e) {
            // Clients drop a session on 401, and the token is not at fault here. The
            // message can reach the response body, so the cause stays in $previous.
            throw new ServiceUnavailableHttpException(null, 'Token verification is temporarily unavailable.', $e);
        } catch (\Throwable $e) {
            throw new AuthenticationException('Invalid token.', 0, $e);
        }

        $user = $this->userResolver->resolve($claims);

        if (null === $user) {
            throw new AuthenticationException('User not found.');
        }

        return new UserBadge($user->getUserIdentifier(), fn () => $user);
    }
}
