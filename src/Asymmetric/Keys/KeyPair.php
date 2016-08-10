<?php
/**
 * Sikker is a PHP 7.0+ Security package that contains security related implementations.
 *
 * @package    NorseBlue\Sikker
 * @version    0.2
 * @author     NorseBlue
 * @license    MIT License
 * @copyright  2016 NorseBlue
 * @link       https://github.com/NorseBlue/Sikker
 */
declare(strict_types = 1);

namespace NorseBlue\Sikker\Asymmetric\Keys;

use InvalidArgumentException;
use NorseBlue\Sikker\OpenSSL\OpenSSL;
use NorseBlue\Sikker\OpenSSL\OpenSSLException;

/**
 * Class KeyPair
 *
 * @package NorseBlue\Sikker\Asymmetric\Keys
 * @since 0.3
 */
class KeyPair
{
    /**
     * @var PrivateKey The KeyPair's private key.
     */
    protected $privateKey;

    /**
     * @var PublicKey The KeyPair's public key.
     */
    protected $publicKey;

    /**
     * KeyPair constructor.
     *
     * @param PrivateKey $privateKey the KeyPair's private key.
     * @param PublicKey $publicKey the KeyPair's public key.
     * @since 0.3
     */
    public function __construct(PrivateKey $privateKey, PublicKey $publicKey)
    {
        $this->privateKey = $privateKey;
        $this->publicKey = $publicKey;
    }

    /**
     * Generates a new KeyPair.
     *
     * @param array $config The OpenSSL configuration.
     * @return KeyPair Returns the newly generated KeyPair.
     * @since 0.3
     */
    public static function generate(array $config = CryptoKey::DEFAULT_CONFIG) : KeyPair
    {
        OpenSSL::resetErrors();
        if (($resource = openssl_pkey_new($config)) === false) {
            // @codeCoverageIgnoreStart
            throw new OpenSSLException(OpenSSL::getErrors(),
                'Could not generate a new key pair.');
            // @codeCoverageIgnoreEnd
        }
        openssl_pkey_export($resource, $privateKey);
        $publicKey = openssl_pkey_get_details($resource)['key'];

        return new self(PrivateKey::fromPEM($privateKey), PublicKey::fromPEM($publicKey));
    }

    /**
     * Creates a KeyPair from PEM formatted key strings.
     *
     * @param string $privateKeyPEM The private key PEM formatted string.
     * @param string $publicKeyPEM The public key PEM formatted string.
     * @return KeyPair The key pair instance containing the private and public keys.
     * @since 0.3
     */
    public static function fromPEM(string $privateKeyPEM, string $publicKeyPEM) : KeyPair
    {
        $privateKey = PrivateKey::fromPEM($privateKeyPEM);
        $publicKey = PublicKey::fromPEM($publicKeyPEM);

        if (!$privateKey->isPairOf($publicKey)) {
            throw new InvalidArgumentException('The given keys do not match.');
        }

        return new self($privateKey, $publicKey);
    }

    /**
     * Gets the KeyPair's private key.
     *
     * @return PrivateKey Returns the private key.
     * @since 0.3
     */
    public function getPrivateKey() : PrivateKey
    {
        return $this->privateKey;
    }

    /**
     * Gets the KeyPair's public key.
     *
     * @return PublicKey Returns the public key.
     * @since 0.3
     */
    public function getPublicKey() : PublicKey
    {
        return $this->publicKey;
    }
}