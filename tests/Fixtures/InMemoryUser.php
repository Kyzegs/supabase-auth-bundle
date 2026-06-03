<?php

declare(strict_types=1);

namespace Kyzegs\SupabaseAuthBundle\Tests\Fixtures;

use Symfony\Component\Security\Core\User\UserInterface;

final class InMemoryUser implements UserInterface
{
    /**
     * @param non-empty-string $identifier
     */
    public function __construct(private string $identifier)
    {
    }

    public function getUserIdentifier(): string
    {
        return $this->identifier;
    }

    public function getRoles(): array
    {
        return ['ROLE_USER'];
    }

    public function eraseCredentials(): void
    {
    }
}
