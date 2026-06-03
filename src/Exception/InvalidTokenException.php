<?php

declare(strict_types=1);

namespace Kyzegs\SupabaseAuthBundle\Exception;

/**
 * Thrown when a Supabase JWT cannot be verified.
 */
final class InvalidTokenException extends \RuntimeException
{
}
