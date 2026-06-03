<?php

declare(strict_types=1);

namespace Kyzegs\SupabaseAuthBundle\Tests\Functional;

use Kyzegs\SupabaseAuthBundle\Contract\SupabaseUserResolverInterface;
use Kyzegs\SupabaseAuthBundle\Security\SupabaseAccessTokenHandler;
use Kyzegs\SupabaseAuthBundle\Security\TestAccessTokenHandler;
use Kyzegs\SupabaseAuthBundle\Tests\Functional\App\StubUserResolver;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Security\Http\AccessToken\AccessTokenHandlerInterface;

final class BundleIntegrationTest extends TestCase
{
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

    private ?TestKernel $kernel = null;

    /**
     * @param array<string, mixed> $bundleConfig
     */
    private function bootContainer(array $bundleConfig): ContainerInterface
    {
        $this->kernel = new TestKernel('test', false, $bundleConfig);
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
}
