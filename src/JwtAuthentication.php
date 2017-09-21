<?php

namespace EnderLab;

use Firebase\JWT\JWT;
use GuzzleHttp\Psr7\Response;
use Interop\Http\ServerMiddleware\DelegateInterface;
use Interop\Http\ServerMiddleware\MiddlewareInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class JwtAuthentication implements MiddlewareInterface
{
    /**
     * @var array
     */
    private $defaultOptions = [
        'privateKey',
        'algorithm'
    ];

    /**
     * @var array
     */
    private $options = [];

    /**
     * @var string
     */
    private $error;

    /**
     * JwtAuthentication constructor.
     *
     * @param array $options
     */
    public function __construct(array $options = [])
    {
        $this->setOptions($options);
    }

    /**
     * @param ServerRequestInterface $request
     * @param DelegateInterface      $delegate
     *
     * @return ResponseInterface
     */
    public function process(ServerRequestInterface $request, DelegateInterface $delegate): ResponseInterface
    {
        $token = $this->getHeaderToken($request->getHeaderLine('Authorization'));
        $parsedToken = $this->checkToken($token);

        if (false === $parsedToken) {
            return (new Response())->withStatus(401)->getBody()->write($this->error);
        }

        return $delegate->process($request);
    }

    /**
     * @param array $options
     */
    private function setOptions(array $options): void
    {
        foreach ($options as $key => $option) {
            if (in_array($key, $this->defaultOptions, true)) {
                $this->options[$key] = $option;
            }
        }
    }

    /**
     * @param string $token
     *
     * @return bool|object
     */
    private function checkToken(string $token)
    {
        try {
            return JWT::decode(
                $token,
                $this->options['privateKey'],
                (array) $this->options['algorithm']
            );
        } catch (\Exception $exception) {
            $this->error = $exception->getMessage();

            return false;
        }
    }

    /**
     * @param string $header
     *
     * @return null|string
     */
    private function getHeaderToken(string $header): ?string
    {
        $token = null;

        if (preg_match("/Bearer\s+(.*)$/i", $header, $matches)) {
            return $matches[1];
        }

        return $token;
    }
}
