<?php

namespace Tests\EnderLab;

use EnderLab\DigestAuthentication;
use PHPUnit\Framework\TestCase;

class DigestAuthenticationTest extends TestCase
{
    public function testInstance()
    {
        $middleware = new DigestAuthentication(['user1' => 'passw1']);
        $this->assertInstanceOf(DigestAuthentication::class, $middleware);
    }
}
