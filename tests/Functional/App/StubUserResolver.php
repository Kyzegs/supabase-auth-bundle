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
        $sub = $claims['sub'] ?? null;

        return \is_string($sub) && '' !== $sub ? new InMemoryUser($sub) : null;
    }
}
