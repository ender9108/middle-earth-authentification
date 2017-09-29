<?php

namespace Tests\EnderLab;

use EnderLab\JwtAuthentication;
use GuzzleHttp\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

class JwtAuthenticationTest extends TestCase
{
    public function testInstance()
    {
        $middleware = new JwtAuthentication([
            'privateKey' => 'test',
            'algorithm'  => 'HS512'
        ]);
        $this->assertInstanceOf(JwtAuthentication::class, $middleware);
    }

    public function testBasicAuth()
    {
        $request = new ServerRequest('GET', '/');
        $params = $request->getServerParams();
    }
}
