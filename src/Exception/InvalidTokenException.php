<?php

declare(strict_types=1);

namespace Kyzegs\SupabaseAuthBundle\Exception;

/**
 * Thrown when a Supabase JWT is rejected: it is malformed, has an invalid
 * signature, or fails claim checks.
 */
final class InvalidTokenException extends \RuntimeException
{
}
