<?php

declare(strict_types=1);

namespace Kyzegs\SupabaseAuthBundle\Exception;

/**
 * Thrown when a Supabase JWT cannot be checked at all, whatever the token: the
 * JWKS cannot be fetched or holds no usable key set, or the bundle is misconfigured.
 */
final class VerificationUnavailableException extends \RuntimeException
{
}
