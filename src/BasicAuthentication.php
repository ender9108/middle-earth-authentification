<?php

namespace EnderLab;

use GuzzleHttp\Psr7\Response;
use Interop\Http\ServerMiddleware\DelegateInterface;
use Interop\Http\ServerMiddleware\MiddlewareInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class BasicAuthentication implements MiddlewareInterface
{
    /**
     * @var array
     */
    private $users = [];

    private $realm = 'basic authentication';

    /**
     * BasicAuthentication constructor.
     *
     * @param array $users
     */
    public function __construct(array $users = [])
    {
        $this->users = $users;
    }

    /**
     * @param ServerRequestInterface $request
     * @param DelegateInterface $delegate
     * @return ResponseInterface
     */
    public function process(ServerRequestInterface $request, DelegateInterface $delegate): ResponseInterface
    {
        $isAuthRequest = (isset($request->getServerParams()['PHP_AUTH_USER']) ? true : false);
        $isAuthRequest = (
            true === $isAuthRequest &&
            true === $this->isValidUser(
                $request->getServerParams()['PHP_AUTH_USER'],
                $request->getServerParams()['PHP_AUTH_PW']
            ) ? true : false
        );

        if (false === $isAuthRequest) {
            return (new Response())->withStatus(401)->withHeader(
                'WWW-Authenticate',
                'Basic realm="' . $this->realm . '"'
            );
        }

        return $delegate->process($request);
    }

    /**
     * @param string $username
     * @param string $password
     *
     * @return bool
     */
    public function isValidUser(string $username, string $password): bool
    {
        if (isset($this->users[$username]) && $this->users[$username] === $password) {
            return true;
        }

        return false;
    }
}
