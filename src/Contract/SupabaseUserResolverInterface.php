<?php

declare(strict_types=1);

namespace Kyzegs\SupabaseAuthBundle\Contract;

use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Resolves an application security user from verified Supabase JWT claims.
 *
 * This is the single piece of application glue the bundle cannot provide:
 * mapping a Supabase identity (typically the `sub` claim) to your own user.
 * Implement it in your application and alias this interface to the
 * implementation in your service configuration.
 */
interface SupabaseUserResolverInterface
{
    /**
     * Resolve a security user from the verified JWT claims.
     *
     * Return null when no user can be derived from the given claims; the
     * token handler converts a null return into an authentication failure.
     *
     * @param array<string, mixed> $claims Verified JWT claims (sub, email, ...)
     */
    public function resolve(array $claims): ?UserInterface;
}
