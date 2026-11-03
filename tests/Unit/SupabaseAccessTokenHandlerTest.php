<?php

declare(strict_types=1);

namespace Kyzegs\SupabaseAuthBundle\Tests\Unit;

use Kyzegs\SupabaseAuthBundle\Contract\SupabaseJwtVerifierInterface;
use Kyzegs\SupabaseAuthBundle\Contract\SupabaseUserResolverInterface;
use Kyzegs\SupabaseAuthBundle\Exception\InvalidTokenException;
use Kyzegs\SupabaseAuthBundle\Exception\VerificationUnavailableException;
use Kyzegs\SupabaseAuthBundle\Security\SupabaseAccessTokenHandler;
use Kyzegs\SupabaseAuthBundle\Tests\Fixtures\InMemoryUser;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpKernel\Exception\ServiceUnavailableHttpException;
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
        $cause = new InvalidTokenException('bad');
        $verifier = $this->createStub(SupabaseJwtVerifierInterface::class);
        $verifier->method('verify')->willThrowException($cause);

        $handler = new SupabaseAccessTokenHandler($verifier, $this->resolver(new InMemoryUser('x')));

        try {
            $handler->getUserBadgeFrom('bad-token');
            self::fail('Expected an AuthenticationException.');
        } catch (AuthenticationException $e) {
            self::assertSame($cause, $e->getPrevious());
        }
    }

    public function testUnexpectedVerifierFailureIsAnAuthenticationFailure(): void
    {
        $verifier = $this->createStub(SupabaseJwtVerifierInterface::class);
        $verifier->method('verify')->willThrowException(new \TypeError('crafted input'));

        $handler = new SupabaseAccessTokenHandler($verifier, $this->resolver(new InMemoryUser('x')));

        $this->expectException(AuthenticationException::class);
        $handler->getUserBadgeFrom('crafted-token');
    }

    public function testUnavailableVerificationAnswers503WithoutExposingTheCause(): void
    {
        $cause = new VerificationUnavailableException('Supabase URL must be an absolute http(s) URL, got "secret".');
        $verifier = $this->createStub(SupabaseJwtVerifierInterface::class);
        $verifier->method('verify')->willThrowException($cause);

        $handler = new SupabaseAccessTokenHandler($verifier, $this->resolver(new InMemoryUser('x')));

        try {
            $handler->getUserBadgeFrom('valid-token');
            self::fail('Expected a ServiceUnavailableHttpException.');
        } catch (ServiceUnavailableHttpException $e) {
            self::assertSame(503, $e->getStatusCode());
            self::assertStringNotContainsString('secret', $e->getMessage());
            self::assertSame($cause, $e->getPrevious());
        }
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
