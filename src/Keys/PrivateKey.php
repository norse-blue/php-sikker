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
 * Class PrivateKey
 *
 * @package NorseBlue\Sikker\Keys
 * @since 0.3
 */
class PrivateKey extends CryptoKey
{
    /**
     * Creates a PrivateKey from the key's string in PEM format.
     *
     * @param string $key The private key string in PEM format.
     * @param string $passphrase The passphrase if exists.
     * @return PrivateKey The PrivateKey object.
     * @since 0.3
     */
    public static function fromPEM(string $key, string $passphrase = '') : PrivateKey
    {
        OpenSSL::isAvailable(true);
        if (($resource = openssl_pkey_get_private($key, $passphrase)) === false) {
            throw new OpenSSLException(OpenSSL::getErrors(), 'Cannot read the given private key.'); // @codeCoverageIgnore
        }

        return new self($resource);
    }
}