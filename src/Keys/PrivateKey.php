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
class PrivateKey
{
    /**
     * @var string The private key string in PEM format.
     */
    protected $key;

    /**
     * @var resource The private key openssl resource.
     */
    protected $resource;

    /**
     * PrivateKey constructor.
     *
     * @param string $key The private key string in PEM format.
     * @param string $passphrase The passphrase if exists.
     * @since 0.3
     */
    public function __construct(string $key, string $passphrase = '')
    {
        OpenSSL::isAvailable(true);

        $this->key = $key;
        if (($this->resource = openssl_pkey_get_private($this->key, $passphrase)) === false) {
            throw new OpenSSLException(OpenSSL::getErrors(), 'Cannot read the given private key.');
        }
    }

    /**
     * Gets the private key's string in PEM format.
     *
     * @return string Returns the private key's string in PEM format.
     * @since 0.3
     */
    public function getKey(): string
    {
        return $this->key;
    }
}