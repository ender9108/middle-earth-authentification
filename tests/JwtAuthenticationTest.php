<?php

namespace Tests\EnderLab;

use EnderLab\BasicAuthentication;
use EnderLab\Dispatcher\Dispatcher;
use EnderLab\JwtAuthentication;
use GuzzleHttp\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

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
}
