<?php

declare(strict_types=1);

namespace Kyzegs\SupabaseAuthBundle\Tests\Functional;

use Kyzegs\SupabaseAuthBundle\Contract\SupabaseUserResolverInterface;
use Kyzegs\SupabaseAuthBundle\SupabaseAuthBundle;
use Kyzegs\SupabaseAuthBundle\Tests\Functional\App\StubJwksEndpoint;
use Kyzegs\SupabaseAuthBundle\Tests\Functional\App\StubUserResolver;
use Psr\Log\NullLogger;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Bundle\SecurityBundle\SecurityBundle;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Attribute\CurrentUser;

final class TestKernel extends Kernel
{
    use MicroKernelTrait;

    /**
     * @param array<string, mixed> $bundleConfig
     */
    public function __construct(
        string $environment,
        bool $debug,
        private array $bundleConfig = [],
    ) {
        parent::__construct($environment, $debug);
    }

    /**
     * Unique per process: without debug, a directory reused across runs serves a container
     * compiled from older code. It must outlive each test, because identical containers
     * share a class that PHP has already loaded and that requires files from its first directory.
     */
    public static function baseDir(): string
    {
        return sys_get_temp_dir() . '/supabase-auth-bundle/' . getmypid();
    }

    public function registerBundles(): iterable
    {
        return [
            new FrameworkBundle(),
            new SecurityBundle(),
            new SupabaseAuthBundle(),
        ];
    }

    public function getCacheDir(): string
    {
        return self::baseDir() . '/cache/' . md5($this->environment . serialize($this->bundleConfig));
    }

    public function getLogDir(): string
    {
        return self::baseDir() . '/log';
    }

    public function me(#[CurrentUser] UserInterface $user): Response
    {
        return new Response($user->getUserIdentifier());
    }

    protected function configureRoutes(RoutingConfigurator $routes): void
    {
        $routes->add('me', '/me')->controller('kernel::me');
    }

    protected function configureContainer(ContainerConfigurator $container, LoaderInterface $loader, ContainerBuilder $builder): void
    {
        $container->extension('framework', [
            'test' => true,
            'secret' => 'test',
            'http_method_override' => false,
            'handle_all_throwables' => true,
            'php_errors' => ['log' => true],
            'cache' => ['app' => 'cache.adapter.array'],
            'http_client' => ['mock_response_factory' => StubJwksEndpoint::class],
        ]);

        // The wiring the README documents, without a user provider.
        $container->extension('security', [
            'firewalls' => [
                'api' => [
                    'stateless' => true,
                    'access_token' => ['token_handler' => 'supabase_auth.token_handler'],
                ],
            ],
            'access_control' => [['path' => '^/', 'roles' => 'ROLE_USER']],
        ]);

        $container->extension('supabase_auth', array_merge(
            ['url' => 'https://project.supabase.co'],
            $this->bundleConfig,
        ));

        $services = $container->services();
        $services->set(StubUserResolver::class)->autowire()->public();
        $services->alias(SupabaseUserResolverInterface::class, StubUserResolver::class)->public();
        $services->set(StubJwksEndpoint::class)->public();
        // The 503 tests log at critical level, which the default logger prints to stderr.
        $services->set('logger', NullLogger::class);
    }
}
