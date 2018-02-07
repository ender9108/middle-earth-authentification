<?php

namespace Tests\EnderLab;

use EnderLab\JwtAuthentication;
use PHPUnit\Framework\TestCase;

class JwtAuthenticationTest extends TestCase
{
    public function testInstance()
    {
        $middleware = new JwtAuthentication();
        $this->assertInstanceOf(JwtAuthentication::class, $middleware);
    }
}
