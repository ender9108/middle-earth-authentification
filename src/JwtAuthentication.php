<?php

namespace EnderLab;

use Firebase\JWT\JWT;
use GuzzleHttp\Psr7\Response;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

class JwtAuthentication implements MiddlewareInterface
{
    const ALGORITHM_HS256 = 'HS256';
    const ALGORITHM_HS384 = 'HS384';
    const ALGORITHM_HS512 = 'HS512';
    const ALGORITHM_RS256 = 'RS256';
    const ALGORITHM_RS384 = 'RS384';
    const ALGORITHM_RS512 = 'RS512';
    const ALGORITHM_ES256 = 'ES256';
    const ALGORITHM_ES384 = 'ES384';
    const ALGORITHM_ES512 = 'ES512';

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
        $currentTime = time();
        $this->options = [
            'secure'        => true,
            'header'        => 'Authorization',
            'regexp'        => "/Bearer\s+(.*)$/i",
            'cookie'        => true,
            'cookieName'    => 'jwt_token',
            'callback'      => null,
            'attribute'     => '_token',
            'algorithm'     => self::ALGORITHM_HS256,
            'secret'        => 'jwtroxx!',
            'rules'         => [
                'jti' => null,
                'iss' => null,
                'aud' => null,
                'sub' => null,
                'iat' => $currentTime,
                'nbf' => $currentTime,
                'exp' => $currentTime
            ]
        ];

        $this->setOptions($options);
    }

    /**
     * @param ServerRequestInterface $request
     * @param RequestHandlerInterface $requestHandler
     *
     * @return ResponseInterface
     * @throws \Exception
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $requestHandler): ResponseInterface
    {
        if (true === $this->options['secure'] && 'https' != $request->getUri()->getScheme()) {
            throw new \Exception('You must use https !');
        }

        $token = $this->getHeaderToken($request->getHeaderLine($this->options['header']));

        if (true === $this->options['cookie']) {
            $token = $this->getCookieToken($request->getCookieParams());
        }

        $parsedToken = $this->checkToken($token);

        if (false === $parsedToken) {
            return (new Response())->withStatus(401)->getBody()->write($this->error);
        }

        if ($this->options["attribute"]) {
            $request = $request->withAttribute($this->options["attribute"], $parsedToken);
        }

        return $requestHandler->handle($request);
    }

    /**
     * @param array $options
     */
    private function setOptions(array $options): void
    {
        foreach ($options as $key => $option) {
            if (in_array($key, $this->options, true)) {
                $this->options[$key] = $option;
            }
        }
    }

    /**
     * @param string $token
     *
     * @return bool|Token
     * @throws \Exception
     */
    private function checkToken(string $token)
    {
        try {
            $token = (new Parser())->parse($token);
            $validator = new ValidationData();

            if (isset($this->options['rules']) && count($this->options['rules']) > 0) {
                foreach ($this->options['rules'] as $key => $value) {
                    switch ($key) {
                        case 'jti':
                            $validator->setId($value);
                            break;
                        case 'iss':
                            $validator->setIssuer($value);
                            break;
                        case 'aud':
                            $validator->setAudience($value);
                            break;
                        case 'sub':
                            $validator->setSubject($value);
                            break;
                        case 'iat':
                        case 'nbf':
                        case 'exp':
                            $validator->setCurrentTime($value);
                            break;
                    }
                }
            }

            $token = (true === $token->validate($validator) ? $token : false);

            if (false !== $token) {
                $signerArgs = $this->getSigner();

                if (false === $token->verify($signerArgs[0], $signerArgs[1])) {
                    return false;
                }
            }

            return $token;
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

        if (preg_match($this->options['regexp'], $header, $matches)) {
            $token = $matches[1];
        }

        return $token;
    }

    /**
     * @param array $cookies
     * @return null|string
     */
    private function getCookieToken(array $cookies): ?string
    {
        $token = null;

        if (isset($cookies[$this->options['cookieName']])) {
            $token = $cookies[$this->options['cookieName']];
        }

        return $token;
    }

    /**
     * @return array
     * @throws \Exception
     */
    private function getSigner(): array
    {
        $signer = 'Sha'.substr($this->options['algorithm'], -1, 3);

        switch ($this->options['algorithm']) {
            case self::ALGORITHM_HS256:
            case self::ALGORITHM_HS384:
            case self::ALGORITHM_HS512:
                return [new $signer, $this->options['secret']];
                break;
            case self::ALGORITHM_ES256:
            case self::ALGORITHM_ES384:
            case self::ALGORITHM_ES512:
            case self::ALGORITHM_RS256:
            case self::ALGORITHM_RS384:
            case self::ALGORITHM_RS512:
                return [new $signer, new Key($this->options['secret'])];
                break;
            default:
                throw new \Exception(sprintf('Algorithm %s is not supported', $this->options['algorithm']));
                break;
        }
    }
}
