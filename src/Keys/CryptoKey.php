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

/**
 * Class CryptoKey
 *
 * @package NorseBlue\Sikker\Keys
 * @since 0.3
 */
abstract class CryptoKey
{
    /**
     * @var string The key string in PEM format.
     */
    protected $key;

    /**
     * @var resource The key OpenSSL resource.
     */
    protected $resource;

    /**
     * Gets the key string in PEM format.
     *
     * @return string Returns the key string in PEM format.
     * @since 0.3
     */
    public function getKey(): string
    {
        return $this->key;
    }

    /**
     * Returns the key OpenSSL resource.
     *
     * @return resource The key OpenSSL resource.
     * @since 0.3
     */
    public function getResource() : resource
    {
        return $this->resource;
    }
}