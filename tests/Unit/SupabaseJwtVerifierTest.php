<?php

declare(strict_types=1);

namespace Kyzegs\SupabaseAuthBundle\Tests\Unit;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Kyzegs\SupabaseAuthBundle\Exception\InvalidTokenException;
use Kyzegs\SupabaseAuthBundle\Exception\VerificationUnavailableException;
use Kyzegs\SupabaseAuthBundle\Service\SupabaseJwtVerifier;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Cache\Adapter\ChainAdapter;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;

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

    public function testVerifiesEs256TokenAgainstASupabaseShapedJwks(): void
    {
        $key = JWKFactory::createECKey('P-256', ['alg' => 'ES256', 'kid' => 'ec-key']);
        $jwks = json_encode(['keys' => [$key->toPublic()->all() + ['use' => 'sig', 'key_ops' => ['verify']]]], JSON_THROW_ON_ERROR);

        $verifier = new SupabaseJwtVerifier(new MockHttpClient(new MockResponse($jwks)), new ArrayAdapter(), new MockClock(), self::SUPABASE_URL);

        self::assertSame('x', $verifier->verify($this->sign(['sub' => 'x', 'iss' => self::ISSUER, 'exp' => time() + 3600], $key))['sub']);
    }

    public function testRejectsAlgorithmOutsideTheConfiguredList(): void
    {
        $verifier = new SupabaseJwtVerifier(
            new MockHttpClient(new MockResponse($this->jwksJson)),
            new ArrayAdapter(),
            new MockClock(),
            self::SUPABASE_URL,
            algorithms: ['ES256'],
        );

        $this->expectException(InvalidTokenException::class);
        $verifier->verify($this->sign(['sub' => 'x', 'iss' => self::ISSUER, 'exp' => time() + 3600]));
    }

    public function testAcceptsUrlWithTrailingSlash(): void
    {
        $verifier = new SupabaseJwtVerifier(new MockHttpClient(new MockResponse($this->jwksJson)), new ArrayAdapter(), new MockClock(), self::SUPABASE_URL . '/');

        self::assertSame('x', $verifier->verify($this->sign(['sub' => 'x', 'iss' => self::ISSUER, 'exp' => time() + 3600]))['sub']);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function claimsThatMustNotBeInTheFuture(): iterable
    {
        yield 'iat' => ['iat'];
        yield 'nbf' => ['nbf'];
    }

    #[DataProvider('claimsThatMustNotBeInTheFuture')]
    public function testRejectsTokenFromTheFuture(string $claim): void
    {
        $token = $this->sign(['sub' => 'x', 'iss' => self::ISSUER, 'exp' => time() + 3600, $claim => time() + 60]);

        $this->expectException(InvalidTokenException::class);
        $this->verifier()->verify($token);
    }

    public function testHonoursLeewayForTokenIssuedAheadOfOurClock(): void
    {
        $token = $this->sign(['sub' => 'x', 'iss' => self::ISSUER, 'exp' => time() + 3600, 'iat' => time() + 5]);

        $verifier = new SupabaseJwtVerifier(
            new MockHttpClient(new MockResponse($this->jwksJson)),
            new ArrayAdapter(),
            new MockClock(),
            self::SUPABASE_URL,
            leeway: 30,
        );

        self::assertSame('x', $verifier->verify($token)['sub']);
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

    /**
     * Well-formed enough to reach the verifier, which throws instead of returning false.
     *
     * @return iterable<string, array{string}>
     */
    public static function tokensTheJwsVerifierThrowsOn(): iterable
    {
        $encode = static fn (string $json): string => rtrim(strtr(base64_encode($json), '+/', '-_'), '=');

        yield 'no payload' => [$encode('{"alg":"RS256"}') . '..' . $encode('signature')];
        yield 'no alg header' => [$encode('{}') . '.' . $encode('{}') . '.' . $encode('signature')];
        yield 'alg not accepted' => [$encode('{"alg":"HS256"}') . '.' . $encode('{}') . '.' . $encode('signature')];
    }

    #[DataProvider('tokensTheJwsVerifierThrowsOn')]
    public function testRejectsTokenTheJwsVerifierThrowsOn(string $token): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->verifier()->verify($token);
    }

    public function testThrowsWhenUrlNotConfigured(): void
    {
        $verifier = new SupabaseJwtVerifier(new MockHttpClient(), new ArrayAdapter(), new MockClock(), '');

        $this->expectException(VerificationUnavailableException::class);
        $verifier->verify('whatever');
    }

    public function testThrowsOnNonHttpUrlAtRuntime(): void
    {
        $verifier = new SupabaseJwtVerifier(new MockHttpClient(), new ArrayAdapter(), new MockClock(), 'not-a-url');

        $this->expectException(VerificationUnavailableException::class);
        $verifier->verify('whatever');
    }

    public function testRejectsTokenMissingMandatoryClaims(): void
    {
        // No `exp` claim — must be rejected even though signature is valid.
        $token = $this->sign(['sub' => 'x', 'iss' => self::ISSUER]);

        $this->expectException(InvalidTokenException::class);
        $this->verifier()->verify($token);
    }

    public function testRejectsTokenWithoutSubject(): void
    {
        $token = $this->sign(['iss' => self::ISSUER, 'exp' => time() + 3600]);

        $this->expectException(InvalidTokenException::class);
        $this->verifier()->verify($token);
    }

    public function testRejectsTokenWithoutAudienceWhenConfigured(): void
    {
        $token = $this->sign(['sub' => 'x', 'iss' => self::ISSUER, 'exp' => time() + 3600]);

        $this->expectException(InvalidTokenException::class);
        $this->verifier(audience: 'authenticated')->verify($token);
    }

    public function testAcceptsTokenWithoutAudienceWhenNotConfigured(): void
    {
        $token = $this->sign(['sub' => 'x', 'iss' => self::ISSUER, 'exp' => time() + 3600]);

        self::assertSame('x', $this->verifier()->verify($token)['sub']);
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

    /**
     * @return iterable<string, array{MockResponse}>
     */
    public static function unusableJwksResponses(): iterable
    {
        yield 'network failure' => [new MockResponse(info: ['error' => 'network down'])];
        yield 'not found' => [new MockResponse('{}', ['http_code' => 404])];
        yield 'server error' => [new MockResponse('{}', ['http_code' => 503])];
        yield 'not json' => [new MockResponse('not json')];
        yield 'no keys member' => [new MockResponse('{}')];
        yield 'empty key set' => [new MockResponse('{"keys":[]}')];
    }

    #[DataProvider('unusableJwksResponses')]
    public function testUnusableJwksIsUnavailableAndNotCached(MockResponse $failure): void
    {
        $verifier = new SupabaseJwtVerifier(
            new MockHttpClient([$failure, new MockResponse($this->jwksJson)]),
            new ArrayAdapter(),
            new MockClock(),
            self::SUPABASE_URL,
        );

        $token = $this->sign(['sub' => 'x', 'iss' => self::ISSUER, 'exp' => time() + 3600]);

        try {
            $verifier->verify($token);
            self::fail('Expected a VerificationUnavailableException.');
        } catch (VerificationUnavailableException) {
        }

        self::assertSame('x', $verifier->verify($token)['sub']);
    }

    public function testCachesUsableJwks(): void
    {
        $http = new MockHttpClient(new MockResponse($this->jwksJson));
        $verifier = new SupabaseJwtVerifier($http, new ArrayAdapter(), new MockClock(), self::SUPABASE_URL);
        $token = $this->sign(['sub' => 'x', 'iss' => self::ISSUER, 'exp' => time() + 3600]);

        $verifier->verify($token);
        $verifier->verify($token);

        self::assertSame(1, $http->getRequestsCount());
    }

    public function testFetchesTheJwksOutsideTheCacheCallback(): void
    {
        // Under FPM a cache callback holds the stampede lock. Fetching inside it queued
        // every worker of an outage behind the timeouts of the workers before it.
        /** @var bool $computing */
        $computing = false;
        $inner = new ArrayAdapter();
        $cache = $this->createStub(CacheInterface::class);
        // Not an arrow function: that would capture $computing by value, and the assertion could never fail.
        $cache->method('get')->willReturnCallback(static function (string $key, callable $callback) use ($inner, &$computing): mixed {
            return $inner->get(
                $key,
                static function (ItemInterface $item, bool &$save) use ($callback, &$computing): mixed {
                    $computing = true;

                    try {
                        return $callback($item, $save);
                    } finally {
                        $computing = false;
                    }
                },
            );
        });

        $http = new MockHttpClient(function () use (&$computing): MockResponse {
            self::assertFalse($computing);

            return new MockResponse($this->jwksJson);
        });
        $verifier = new SupabaseJwtVerifier($http, $cache, new MockClock(), self::SUPABASE_URL);

        $verifier->verify($this->sign(['sub' => 'x', 'iss' => self::ISSUER, 'exp' => time() + 3600]));

        self::assertSame(1, $http->getRequestsCount());
    }

    public function testRefetchesTheJwksOnlyAfterTheConfiguredTtl(): void
    {
        $clock = new MockClock();
        $http = new MockHttpClient([new MockResponse($this->jwksJson), new MockResponse($this->jwksJson)]);
        $verifier = new SupabaseJwtVerifier($http, new ArrayAdapter(clock: $clock), $clock, self::SUPABASE_URL, jwksTtl: 60);
        $token = $this->sign(['sub' => 'x', 'iss' => self::ISSUER, 'exp' => time() + 3600]);

        $verifier->verify($token);
        $clock->sleep(59);
        $verifier->verify($token);
        self::assertSame(1, $http->getRequestsCount());

        $clock->sleep(2);
        $verifier->verify($token);
        self::assertSame(2, $http->getRequestsCount());
    }

    public function testNeverCachesTheJwksWithATtlOfZero(): void
    {
        $directory = sys_get_temp_dir() . '/supabase-auth-bundle-test-' . uniqid('', true);
        $cache = new ChainAdapter([new ArrayAdapter(), new FilesystemAdapter(directory: $directory)]);
        $http = new MockHttpClient([new MockResponse($this->jwksJson), new MockResponse($this->jwksJson)]);
        $verifier = new SupabaseJwtVerifier($http, $cache, new MockClock(), self::SUPABASE_URL, jwksTtl: 0);
        $token = $this->sign(['sub' => 'x', 'iss' => self::ISSUER, 'exp' => time() + 3600]);

        try {
            $verifier->verify($token);
            $verifier->verify($token);
        } finally {
            (new Filesystem())->remove($directory);
        }

        self::assertSame(2, $http->getRequestsCount());
    }

    public function testLimitsTheJwksRequestDuration(): void
    {
        $response = new MockResponse($this->jwksJson);
        $verifier = new SupabaseJwtVerifier(new MockHttpClient($response), new ArrayAdapter(), new MockClock(), self::SUPABASE_URL);

        $verifier->verify($this->sign(['sub' => 'x', 'iss' => self::ISSUER, 'exp' => time() + 3600]));

        self::assertEquals(5, $response->getRequestOptions()['timeout']);
        self::assertEquals(5, $response->getRequestOptions()['max_duration']);
    }

    public function testThrowsOnUnsupportedAlgorithm(): void
    {
        $verifier = new SupabaseJwtVerifier(
            new MockHttpClient(new MockResponse($this->jwksJson)),
            new ArrayAdapter(),
            new MockClock(),
            self::SUPABASE_URL,
            algorithms: ['HS256'],
        );

        $token = $this->sign(['sub' => 'x', 'iss' => self::ISSUER, 'exp' => time() + 3600]);

        $this->expectException(VerificationUnavailableException::class);
        $verifier->verify($token);
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function sign(array $claims, ?JWK $key = null): string
    {
        $key ??= $this->privateKey;
        $builder = new JWSBuilder(new AlgorithmManager([new RS256(), new ES256()]));

        $jws = $builder
            ->create()
            ->withPayload(json_encode($claims, JSON_THROW_ON_ERROR))
            ->addSignature($key, ['alg' => $key->get('alg')])
            ->build();

        return (new CompactSerializer())->serialize($jws, 0);
    }

    private function verifier(?string $audience = null): SupabaseJwtVerifier
    {
        $http = new MockHttpClient(new MockResponse($this->jwksJson));

        return new SupabaseJwtVerifier($http, new ArrayAdapter(), new MockClock(), self::SUPABASE_URL, audience: $audience);
    }
}
