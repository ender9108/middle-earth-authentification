<?php

namespace Tests\EnderLab;

use EnderLab\BasicAuthentication;
use EnderLab\DigestAuthentication;
use EnderLab\Dispatcher\Dispatcher;
use EnderLab\JwtAuthentication;
use GuzzleHttp\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

class DigestAuthenticationTest extends TestCase
{
    public function testInstance()
    {
        $middleware = new DigestAuthentication(['user1' => 'passw1']);
        $this->assertInstanceOf(DigestAuthentication::class, $middleware);
    }
}
