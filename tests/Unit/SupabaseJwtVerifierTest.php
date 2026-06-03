<?php

declare(strict_types=1);

namespace Kyzegs\SupabaseAuthBundle\Tests\Unit;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Kyzegs\SupabaseAuthBundle\Exception\InvalidTokenException;
use Kyzegs\SupabaseAuthBundle\Service\SupabaseJwtVerifier;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpClient\Exception\TransportException;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

final class SupabaseJwtVerifierTest extends TestCase
{
    private const string SUPABASE_URL = 'https://project.supabase.co';
    private const string ISSUER = self::SUPABASE_URL . '/auth/v1';

    private JWK $privateKey;
    private string $jwksJson;

    protected function setUp(): void
    {
        $this->privateKey = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig', 'kid' => 'test-key']);
        $this->jwksJson = json_encode(['keys' => [$this->privateKey->toPublic()->all()]], JSON_THROW_ON_ERROR);
    }

    public function testVerifiesValidToken(): void
    {
        $token = $this->sign([
            'sub' => '11111111-1111-1111-1111-111111111111',
            'iss' => self::ISSUER,
            'exp' => time() + 3600,
        ]);

        $claims = $this->verifier()->verify($token);

        self::assertSame('11111111-1111-1111-1111-111111111111', $claims['sub']);
        self::assertSame(self::ISSUER, $claims['iss']);
    }

    public function testRejectsExpiredToken(): void
    {
        $token = $this->sign(['sub' => 'x', 'iss' => self::ISSUER, 'exp' => time() - 10]);

        $this->expectException(InvalidTokenException::class);
        $this->verifier()->verify($token);
    }

    public function testRejectsWrongIssuer(): void
    {
        $token = $this->sign(['sub' => 'x', 'iss' => 'https://evil.example/auth/v1', 'exp' => time() + 3600]);

        $this->expectException(InvalidTokenException::class);
        $this->verifier()->verify($token);
    }

    public function testRejectsTokenSignedWithUnknownKey(): void
    {
        $otherKey = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig', 'kid' => 'other']);
        $token = $this->sign(['sub' => 'x', 'iss' => self::ISSUER, 'exp' => time() + 3600], $otherKey);

        $this->expectException(InvalidTokenException::class);
        $this->verifier()->verify($token);
    }

    public function testRejectsMalformedToken(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->verifier()->verify('not-a-jwt');
    }

    public function testThrowsWhenUrlNotConfigured(): void
    {
        $verifier = new SupabaseJwtVerifier(new MockHttpClient(), new ArrayAdapter(), new MockClock(), '');

        $this->expectException(InvalidTokenException::class);
        $verifier->verify('whatever');
    }

    public function testRejectsTokenMissingMandatoryClaims(): void
    {
        // No `exp` claim — must be rejected even though signature is valid.
        $token = $this->sign(['sub' => 'x', 'iss' => self::ISSUER]);

        $this->expectException(InvalidTokenException::class);
        $this->verifier()->verify($token);
    }

    public function testHonoursLeewayForRecentlyExpiredToken(): void
    {
        // Expired 5s ago, but a 30s leeway keeps it valid (clock skew tolerance).
        $token = $this->sign(['sub' => 'x', 'iss' => self::ISSUER, 'exp' => time() - 5]);

        $verifier = new SupabaseJwtVerifier(
            new MockHttpClient(new MockResponse($this->jwksJson)),
            new ArrayAdapter(),
            new MockClock(),
            self::SUPABASE_URL,
            leeway: 30,
        );

        self::assertSame('x', $verifier->verify($token)['sub']);
    }

    public function testEnforcesAudienceWhenConfigured(): void
    {
        $token = $this->sign(['sub' => 'x', 'iss' => self::ISSUER, 'exp' => time() + 3600, 'aud' => 'authenticated']);

        $ok = $this->verifier(audience: 'authenticated');
        self::assertSame('x', $ok->verify($token)['sub']);

        $this->expectException(InvalidTokenException::class);
        $this->verifier(audience: 'someone-else')->verify($token);
    }

    public function testWrapsJwksHttpFailure(): void
    {
        $verifier = new SupabaseJwtVerifier(
            new MockHttpClient(static fn (): never => throw new TransportException('network down')),
            new ArrayAdapter(),
            new MockClock(),
            self::SUPABASE_URL,
        );

        $token = $this->sign(['sub' => 'x', 'iss' => self::ISSUER, 'exp' => time() + 3600]);

        $this->expectException(InvalidTokenException::class);
        $verifier->verify($token);
    }

    public function testWrapsMalformedJwksResponse(): void
    {
        $verifier = new SupabaseJwtVerifier(
            new MockHttpClient(new MockResponse('not json')),
            new ArrayAdapter(),
            new MockClock(),
            self::SUPABASE_URL,
        );

        $token = $this->sign(['sub' => 'x', 'iss' => self::ISSUER, 'exp' => time() + 3600]);

        $this->expectException(InvalidTokenException::class);
        $verifier->verify($token);
    }

    public function testRejectsUnsupportedAlgorithm(): void
    {
        $verifier = new SupabaseJwtVerifier(
            new MockHttpClient(new MockResponse($this->jwksJson)),
            new ArrayAdapter(),
            new MockClock(),
            self::SUPABASE_URL,
            algorithms: ['HS256'],
        );

        $token = $this->sign(['sub' => 'x', 'iss' => self::ISSUER, 'exp' => time() + 3600]);

        $this->expectException(InvalidTokenException::class);
        $verifier->verify($token);
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function sign(array $claims, ?JWK $key = null): string
    {
        $key ??= $this->privateKey;
        $builder = new JWSBuilder(new AlgorithmManager([new RS256()]));

        $jws = $builder
            ->create()
            ->withPayload(json_encode($claims, JSON_THROW_ON_ERROR))
            ->addSignature($key, ['alg' => 'RS256'])
            ->build();

        return (new CompactSerializer())->serialize($jws, 0);
    }

    private function verifier(?string $audience = null): SupabaseJwtVerifier
    {
        $http = new MockHttpClient(new MockResponse($this->jwksJson));

        return new SupabaseJwtVerifier($http, new ArrayAdapter(), new MockClock(), self::SUPABASE_URL, audience: $audience);
    }
}
