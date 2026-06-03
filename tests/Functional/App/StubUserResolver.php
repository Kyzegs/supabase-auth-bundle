<?php

declare(strict_types=1);

namespace Kyzegs\SupabaseAuthBundle\Tests\Functional\App;

use Kyzegs\SupabaseAuthBundle\Contract\SupabaseUserResolverInterface;
use Kyzegs\SupabaseAuthBundle\Tests\Fixtures\InMemoryUser;
use Symfony\Component\Security\Core\User\UserInterface;

final class StubUserResolver implements SupabaseUserResolverInterface
{
    public function resolve(array $claims): ?UserInterface
    {
        $sub = isset($claims['sub']) ? (string) $claims['sub'] : '';

        if ('' === $sub) {
            return null;
        }

        return new InMemoryUser($sub);
    }
}
