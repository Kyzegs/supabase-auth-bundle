<?php

declare(strict_types=1);

namespace Kyzegs\SupabaseAuthBundle\Contract;

use Kyzegs\SupabaseAuthBundle\Exception\InvalidTokenException;
use Kyzegs\SupabaseAuthBundle\Exception\VerificationUnavailableException;

/**
 * Verifies the signature and standard claims of a Supabase-issued JWT.
 */
interface SupabaseJwtVerifierInterface
{
    /**
     * Verify the token and return its claims.
     *
     * @return array<string, mixed> The verified JWT claims
     *
     * @throws InvalidTokenException            When the token is malformed, has an
     *                                          invalid signature, or fails claim checks
     * @throws VerificationUnavailableException When the JWKS cannot be fetched or is
     *                                          unusable, or the bundle is misconfigured
     */
    public function verify(#[\SensitiveParameter] string $token): array;
}
