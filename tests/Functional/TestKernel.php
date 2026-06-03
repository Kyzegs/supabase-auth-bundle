<?php

declare(strict_types=1);

namespace Kyzegs\SupabaseAuthBundle\Tests\Functional;

use Kyzegs\SupabaseAuthBundle\Contract\SupabaseUserResolverInterface;
use Kyzegs\SupabaseAuthBundle\SupabaseAuthBundle;
use Kyzegs\SupabaseAuthBundle\Tests\Functional\App\StubUserResolver;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Kernel;

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

    public function registerBundles(): iterable
    {
        return [
            new FrameworkBundle(),
            new SupabaseAuthBundle(),
        ];
    }

    public function getCacheDir(): string
    {
        return sys_get_temp_dir() . '/supabase-auth-bundle/cache/' . md5(serialize($this->bundleConfig));
    }

    public function getLogDir(): string
    {
        return sys_get_temp_dir() . '/supabase-auth-bundle/log';
    }

    protected function configureContainer(ContainerConfigurator $container, LoaderInterface $loader, ContainerBuilder $builder): void
    {
        $container->extension('framework', [
            'test' => true,
            'secret' => 'test',
            'http_method_override' => false,
            'handle_all_throwables' => true,
            'php_errors' => ['log' => true],
        ]);

        $container->extension('supabase_auth', array_merge(
            ['url' => 'https://project.supabase.co'],
            $this->bundleConfig,
        ));

        $services = $container->services();
        $services->set(StubUserResolver::class)->autowire()->public();
        $services->alias(SupabaseUserResolverInterface::class, StubUserResolver::class)->public();
    }
}
