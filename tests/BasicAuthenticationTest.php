<?php

namespace Tests\EnderLab;

use EnderLab\BasicAuthentication;
use EnderLab\Dispatcher\Dispatcher;
use EnderLab\JwtAuthentication;
use GuzzleHttp\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

class BasicAuthenticationTest extends TestCase
{
    public function testInstance()
    {
        $middleware = new BasicAuthentication(['user1' => 'passw1']);
        $this->assertInstanceOf(BasicAuthentication::class, $middleware);
    }

    public function testSuccessBasicAuth()
    {
        $params = [];
        $params['PHP_AUTH_USER'] = 'user1';
        $params['PHP_AUTH_PW'] = 'passw1';
        $request = new ServerRequest('GET', '/', [], null, '1.1', $params);
        $delegate = new Dispatcher();

        $middleware = new BasicAuthentication(['user1' => 'passw1']);
        $response = $middleware->process($request, $delegate);
        $this->assertInstanceOf(ResponseInterface::class, $response);
        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testErrorBasicAuth()
    {
        $params = [];
        $params['PHP_AUTH_USER'] = 'user1';
        $params['PHP_AUTH_PW'] = 'passw1';
        $request = new ServerRequest('GET', '/', [], null, '1.1', $params);
        $delegate = new Dispatcher();

        $middleware = new BasicAuthentication(['user2' => 'passw2']);
        $response = $middleware->process($request, $delegate);
        $this->assertInstanceOf(ResponseInterface::class, $response);
        $this->assertEquals(401, $response->getStatusCode());
    }
}
