<?php

namespace EnderLab;

use GuzzleHttp\Psr7\Response;
use Interop\Http\ServerMiddleware\DelegateInterface;
use Interop\Http\ServerMiddleware\MiddlewareInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class DigestAuthentication implements MiddlewareInterface
{
    /**
     * @var array
     */
    private $users = [];

    /**
     * @var string
     */
    private $nonce;

    /**
     * @var string
     */
    private $realm = 'digest authentication';

    /**
     * DigestAuthentication constructor.
     *
     * @param array       $users
     * @param string|null $nonce
     * @param string|null $realm
     */
    public function __construct(array $users, string $nonce = null, string $realm = null)
    {
        $this->users = $users;
        $this->nonce = (null === $nonce) ? uniqid() : $nonce;
        $this->realm = (null === $realm) ? $this->realm : $realm;
    }

    /**
     * @param ServerRequestInterface $request
     * @param DelegateInterface      $delegate
     *
     * @return ResponseInterface
     */
    public function process(ServerRequestInterface $request, DelegateInterface $delegate): ResponseInterface
    {
        $dataRequest = $this->parseDigestHttp($request->getServerParams()['PHP_AUTH_DIGEST']);
        $isAuthRequest = (0 === count($dataRequest)) ? false : true;
        $isAuthRequest = (
            $this->buildValidResponse($dataRequest, $request->getMethod()) &&
            true === $isAuthRequest ?
            true : false
        );

        if (false === $isAuthRequest) {
            return (new Response()
            )->withStatus(401)->withHeader(
                'WWW-Authenticate',
                'Basic realm="' . $this->realm . '"' .
                ',qop="auth",nonce="' . $this->nonce . '"' .
                ',opaque="' . md5($this->realm) . '"'
            );
        }

        return $delegate->process($request);
    }

    /**
     * @param string $txt
     *
     * @return array
     */
    private function parseDigestHttp(string $txt): array
    {
        $parts = [
            'nonce'    => 1,
            'nc'       => 1,
            'cnonce'   => 1,
            'qop'      => 1,
            'username' => 1,
            'uri'      => 1,
            'response' => 1
        ];
        $return = [];
        $keys = implode('|', array_keys($parts));

        preg_match_all('@(' . $keys . ')=(?:([\'"])([^\2]+?)\2|([^\s,]+))@', $txt, $matches, PREG_SET_ORDER);

        foreach ($matches as $m) {
            $return[$m[1]] = $m[3] ? $m[3] : $m[4];
            unset($parts[$m[1]]);
        }

        return $return;
    }

    /**
     * @param array  $result
     * @param string $method
     *
     * @return bool
     */
    private function buildValidResponse(array $result, string $method): bool
    {
        $a1 = md5($result['username'] . ':' . $this->realm . ':' . $this->users[$result['username']]);
        $a2 = md5($method . ':' . $result['uri']);

        return md5($a1 . ':' . $result['nonce'] . ':' . $result['nc'] . ':' . $result['cnonce'] . ':' . $result['qop'] . ':' . $a2);
    }
}
