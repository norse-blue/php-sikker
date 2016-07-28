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
class PublicKey
{
    /**
     * @var string The public key string in PEM format.
     */
    protected $key;

    /**
     * @var resource The public key openssl resource.
     */
    protected $resource;

    /**
     * PublicKey constructor.
     *
     * @param string $key The public key string in PEM format.
     * @since 0.3
     */
    public function __construct(string $key)
    {
        OpenSSL::isAvailable(true);

        $this->key = $key;
        if (($this->resource = openssl_pkey_get_public($this->key)) === false) {
            throw new OpenSSLException(OpenSSL::getErrors(), 'Cannot read the given public key.');
        }
    }

    /**
     * Gets the public key's string in PEM format.
     *
     * @return string Returns the key's public string in PEM format.
     * @since 0.3
     */
    public function getKey(): string
    {
        return $this->key;
    }
}