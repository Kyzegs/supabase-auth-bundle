<?php

declare(strict_types=1);

namespace Kyzegs\SupabaseAuthBundle\Tests\Unit;

use Kyzegs\SupabaseAuthBundle\Contract\SupabaseJwtVerifierInterface;
use Kyzegs\SupabaseAuthBundle\Contract\SupabaseUserResolverInterface;
use Kyzegs\SupabaseAuthBundle\Exception\InvalidTokenException;
use Kyzegs\SupabaseAuthBundle\Security\SupabaseAccessTokenHandler;
use Kyzegs\SupabaseAuthBundle\Tests\Fixtures\InMemoryUser;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;

final class SupabaseAccessTokenHandlerTest extends TestCase
{
    public function testReturnsUserBadgeForValidToken(): void
    {
        $user = new InMemoryUser('user-123');
        $handler = new SupabaseAccessTokenHandler(
            $this->verifier(['sub' => 'user-123']),
            $this->resolver($user),
        );

        $badge = $handler->getUserBadgeFrom('valid-token');

        self::assertSame('user-123', $badge->getUserIdentifier());
        self::assertSame($user, $badge->getUser());
    }

    public function testThrowsWhenTokenInvalid(): void
    {
        $verifier = $this->createStub(SupabaseJwtVerifierInterface::class);
        $verifier->method('verify')->willThrowException(new InvalidTokenException('bad'));

        $handler = new SupabaseAccessTokenHandler($verifier, $this->resolver(new InMemoryUser('x')));

        $this->expectException(AuthenticationException::class);
        $handler->getUserBadgeFrom('bad-token');
    }

    public function testThrowsWhenUserNotResolved(): void
    {
        $handler = new SupabaseAccessTokenHandler(
            $this->verifier(['sub' => 'ghost']),
            $this->resolver(null),
        );

        $this->expectException(AuthenticationException::class);
        $handler->getUserBadgeFrom('valid-token');
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function verifier(array $claims): SupabaseJwtVerifierInterface
    {
        $verifier = $this->createStub(SupabaseJwtVerifierInterface::class);
        $verifier->method('verify')->willReturn($claims);

        return $verifier;
    }

    private function resolver(?UserInterface $user): SupabaseUserResolverInterface
    {
        $resolver = $this->createStub(SupabaseUserResolverInterface::class);
        $resolver->method('resolve')->willReturn($user);

        return $resolver;
    }
}
