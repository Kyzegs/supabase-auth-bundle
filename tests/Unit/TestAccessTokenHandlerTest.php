<?php

declare(strict_types=1);

namespace Kyzegs\SupabaseAuthBundle\Tests\Unit;

use Kyzegs\SupabaseAuthBundle\Contract\SupabaseUserResolverInterface;
use Kyzegs\SupabaseAuthBundle\Security\TestAccessTokenHandler;
use Kyzegs\SupabaseAuthBundle\Tests\Fixtures\InMemoryUser;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

final class TestAccessTokenHandlerTest extends TestCase
{
    public function testResolvesUserFromPrefixedToken(): void
    {
        $user = new InMemoryUser('abc');
        $resolver = $this->createMock(SupabaseUserResolverInterface::class);
        $resolver->expects(self::once())
            ->method('resolve')
            ->with(['sub' => 'abc'])
            ->willReturn($user);

        $handler = new TestAccessTokenHandler($resolver);
        $badge = $handler->getUserBadgeFrom('test-user-abc');

        self::assertSame('abc', $badge->getUserIdentifier());
    }

    public function testRejectsTokenWithoutPrefix(): void
    {
        $handler = new TestAccessTokenHandler($this->createStub(SupabaseUserResolverInterface::class));

        $this->expectException(AuthenticationException::class);
        $handler->getUserBadgeFrom('abc');
    }

    public function testThrowsWhenUserNotResolved(): void
    {
        $resolver = $this->createStub(SupabaseUserResolverInterface::class);
        $resolver->method('resolve')->willReturn(null);

        $handler = new TestAccessTokenHandler($resolver);

        $this->expectException(AuthenticationException::class);
        $handler->getUserBadgeFrom('test-user-ghost');
    }

    public function testHonoursCustomPrefix(): void
    {
        $resolver = $this->createMock(SupabaseUserResolverInterface::class);
        $resolver->expects(self::once())
            ->method('resolve')
            ->with(['sub' => '42'])
            ->willReturn(new InMemoryUser('42'));

        $handler = new TestAccessTokenHandler($resolver, 'dev-');
        $handler->getUserBadgeFrom('dev-42');
    }
}
