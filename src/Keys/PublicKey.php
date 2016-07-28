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

namespace NorseBlue\Sikker\Keys;

use NorseBlue\Sikker\OpenSSL\OpenSSL;
use NorseBlue\Sikker\OpenSSL\OpenSSLException;

/**
 * Class PublicKey
 *
 * @package NorseBlue\Sikker\Keys
 * @since 0.3
 */
class PublicKey extends CryptoKey
{
    /**
     * Creates a PublicKey from the key's string in PEM format.
     *
     * @param string $key The private key string in PEM format.
     * @return PublicKey The PrivateKey object.
     * @since 0.3
     */
    public static function fromPEM(string $key) : PublicKey
    {
        OpenSSL::isAvailable(true);
        if (($resource = openssl_pkey_get_public($key)) === false) {
            throw new OpenSSLException(OpenSSL::getErrors(), 'Cannot read the given public key.');      // @codeCoverageIgnore
        }

        return new self($resource);
    }
}