<?php

declare(strict_types=1);

namespace Kyzegs\SupabaseAuthBundle\Tests\Functional;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Kyzegs\SupabaseAuthBundle\Contract\SupabaseUserResolverInterface;
use Kyzegs\SupabaseAuthBundle\Security\SupabaseAccessTokenHandler;
use Kyzegs\SupabaseAuthBundle\Security\TestAccessTokenHandler;
use Kyzegs\SupabaseAuthBundle\Tests\Functional\App\StubJwksEndpoint;
use Kyzegs\SupabaseAuthBundle\Tests\Functional\App\StubUserResolver;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Http\AccessToken\AccessTokenHandlerInterface;

final class BundleIntegrationTest extends TestCase
{
    private const string ISSUER = 'https://project.supabase.co/auth/v1';

    public function testTokenHandlerIsSupabaseHandlerByDefault(): void
    {
        $container = $this->bootContainer(['test_mode' => false]);

        $handler = $container->get('supabase_auth.token_handler');

        self::assertInstanceOf(SupabaseAccessTokenHandler::class, $handler);
        self::assertInstanceOf(AccessTokenHandlerInterface::class, $handler);
    }

    public function testTokenHandlerIsTestHandlerWhenTestModeEnabled(): void
    {
        $container = $this->bootContainer(['test_mode' => true]);

        $handler = $container->get('supabase_auth.token_handler');

        self::assertInstanceOf(TestAccessTokenHandler::class, $handler);
    }

    public function testResolverInterfaceIsResolvedFromApplication(): void
    {
        $container = $this->bootContainer(['test_mode' => true]);

        self::assertInstanceOf(
            StubUserResolver::class,
            $container->get(SupabaseUserResolverInterface::class),
        );
    }

    public function testAcceptsEnvVarUrl(): void
    {
        // Regression: an "%env()%" url is unresolved at compile time, so the
        // container must still build. URL format is validated at runtime instead.
        $container = $this->bootContainer(['url' => '%env(SUPABASE_URL)%']);

        self::assertTrue($container->has('supabase_auth.token_handler'));
    }

    public function testRejectsUnsupportedAlgorithmConfiguration(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->bootContainer(['algorithms' => ['HS256']]);
    }

    public function testRejectsNegativeLeeway(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->bootContainer(['leeway' => -1]);
    }

    public function testRefusesEnvVarTestMode(): void
    {
        // Regression: the placeholder is a truthy string at compile time, so with the
        // same env expression used elsewhere, X=0 still selected the test handler.
        $_SERVER['SUPABASE_TEST_MODE'] = '0';

        try {
            $this->expectException(InvalidConfigurationException::class);
            $this->bootContainer(['test_mode' => '%env(bool:SUPABASE_TEST_MODE)%', 'test_token_prefix' => '%env(bool:SUPABASE_TEST_MODE)%']);
        } finally {
            unset($_SERVER['SUPABASE_TEST_MODE']);
        }
    }

    public function testRefusesTestModeInProd(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->bootContainer(['test_mode' => true], 'prod');
    }

    public function testBootsInProdWithoutTestMode(): void
    {
        $container = $this->bootContainer([], 'prod');

        self::assertInstanceOf(SupabaseAccessTokenHandler::class, $container->get('supabase_auth.token_handler'));
    }

    public function testFirewallToleratesClockSkewByDefault(): void
    {
        // Regression: at a leeway of 0, a fresh token whose iat is ahead of this server's clock
        // answered 401, which clients treat as a dead session.
        $jwks = $this->jwksEndpoint($this->bootContainer([]));
        [$jwks->body, $token] = $this->jwksAndToken(['sub' => 'user-1', 'iss' => self::ISSUER, 'exp' => time() + 3600, 'iat' => time() + 5]);

        self::assertSame(200, $this->request($token)->getStatusCode());
    }

    public function testFirewallLetsAValidTokenThrough(): void
    {
        $jwks = $this->jwksEndpoint($this->bootContainer([]));
        [$jwks->body, $token] = $this->jwksAndToken(['sub' => 'user-1', 'iss' => self::ISSUER, 'exp' => time() + 3600]);

        $response = $this->request($token);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('user-1', $response->getContent());
    }

    public function testFirewallAnswers401WithoutAToken(): void
    {
        $this->bootContainer([]);

        self::assertSame(401, $this->request(null)->getStatusCode());
    }

    public function testFirewallAnswers401ForAGarbageTokenWithoutFetchingTheJwks(): void
    {
        $jwks = $this->jwksEndpoint($this->bootContainer([]));

        self::assertSame(401, $this->request('garbage')->getStatusCode());
        self::assertSame(0, $jwks->requests);
    }

    public function testFirewallAnswers401WhenTheResolverFindsNoUser(): void
    {
        $jwks = $this->jwksEndpoint($this->bootContainer([]));
        [$jwks->body, $token] = $this->jwksAndToken(['sub' => '', 'iss' => self::ISSUER, 'exp' => time() + 3600]);

        self::assertSame(401, $this->request($token)->getStatusCode());
    }

    public function testFirewallAnswers503WhenTheJwksIsUnavailable(): void
    {
        $this->bootContainer([]);
        [, $token] = $this->jwksAndToken(['sub' => 'user-1', 'iss' => self::ISSUER, 'exp' => time() + 3600]);

        $response = $this->request($token);

        self::assertSame(503, $response->getStatusCode());
        self::assertStringNotContainsString('supabase.co', (string) $response->getContent());
    }

    public function testFirewallAcceptsOnlyPrefixedTokensInTestMode(): void
    {
        $this->bootContainer(['test_mode' => true]);

        $response = $this->request('test-user-abc');

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('abc', $response->getContent());
        self::assertSame(401, $this->request('abc')->getStatusCode());
    }

    /**
     * @param array<string, mixed> $claims
     *
     * @return array{string, string} A Supabase-shaped JWKS and a token signed by its key
     */
    private function jwksAndToken(array $claims): array
    {
        $key = JWKFactory::createECKey('P-256', ['alg' => 'ES256', 'kid' => 'test-key']);

        $jws = (new JWSBuilder(new AlgorithmManager([new ES256()])))
            ->create()
            ->withPayload(json_encode($claims, JSON_THROW_ON_ERROR))
            ->addSignature($key, ['alg' => 'ES256'])
            ->build();

        return [
            json_encode(['keys' => [$key->toPublic()->all() + ['use' => 'sig', 'key_ops' => ['verify']]]], JSON_THROW_ON_ERROR),
            (new CompactSerializer())->serialize($jws, 0),
        ];
    }

    private function request(?string $token): Response
    {
        self::assertNotNull($this->kernel);

        return $this->kernel->handle(Request::create(
            '/me',
            server: null === $token ? [] : ['HTTP_AUTHORIZATION' => 'Bearer ' . $token],
        ));
    }

    private function jwksEndpoint(ContainerInterface $container): StubJwksEndpoint
    {
        $endpoint = $container->get(StubJwksEndpoint::class);
        self::assertInstanceOf(StubJwksEndpoint::class, $endpoint);

        return $endpoint;
    }

    private ?TestKernel $kernel = null;

    /**
     * @param array<string, mixed> $bundleConfig
     */
    private function bootContainer(array $bundleConfig, string $environment = 'test'): ContainerInterface
    {
        $this->kernel = new TestKernel($environment, false, $bundleConfig);
        $this->kernel->boot();

        $container = $this->kernel->getContainer()->get('test.service_container');

        if (!$container instanceof ContainerInterface) {
            throw new \RuntimeException('The test service container is not available.');
        }

        return $container;
    }

    protected function tearDown(): void
    {
        $this->kernel?->shutdown();
        $this->kernel = null;

        // Booting the kernel registers a Symfony exception handler; restore it
        // so PHPUnit does not flag the test as risky.
        restore_exception_handler();
    }

    public static function tearDownAfterClass(): void
    {
        (new Filesystem())->remove(TestKernel::baseDir());
    }
}
