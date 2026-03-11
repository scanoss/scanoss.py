<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\Routing;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Exception\MethodNotAllowedException;
use Symfony\Component\Routing\Exception\ResourceNotFoundException;
use Symfony\Component\Routing\Matcher\UrlMatcherInterface;

class Router implements RouterInterface
{
    private RouteCollection $routes;
    private UrlMatcherInterface $matcher;
    private array $options;

    public function __construct(RouteCollection $routes, array $options = [])
    {
        $this->routes = $routes;
        $this->options = array_merge([
            'cache_dir' => null,
            'debug' => false,
            'strict_requirements' => true,
        ], $options);
    }

    public function match(string $pathinfo): array
    {
        return $this->getMatcher()->match($pathinfo);
    }

    public function matchRequest(Request $request): array
    {
        $pathinfo = $request->getPathInfo();
        $method = $request->getMethod();

        try {
            $parameters = $this->match($pathinfo);
        } catch (ResourceNotFoundException $e) {
            throw new ResourceNotFoundException(
                sprintf('No route found for "%s %s"', $method, $pathinfo),
                0,
                $e
            );
        }

        if (isset($parameters['_method'])) {
            $allowedMethods = explode('|', $parameters['_method']);
            if (!in_array($method, $allowedMethods, true)) {
                throw new MethodNotAllowedException($allowedMethods);
            }
        }

        return $parameters;
    }

    public function getRouteCollection(): RouteCollection
    {
        return $this->routes;
    }

    public function addRoute(string $name, Route $route): void
    {
        $this->routes->add($name, $route);
    }

    private function getMatcher(): UrlMatcherInterface
    {
        if (!isset($this->matcher)) {
            $this->matcher = new UrlMatcher($this->routes, new RequestContext());
        }

        return $this->matcher;
    }
}