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
use RuntimeException;

/**
 * Class CryptoKey
 *
 * @package NorseBlue\Sikker\Keys
 * @since 0.3
 */
abstract class CryptoKey
{
    const DEFAULT_CONFIG = [
        'digest_alg' => 'sha256',
        'private_key_type' => 0, // OPENSSL_KEYTYPE_RSA
        'private_key_bits' => 1024
    ];

    /**
     * @var resource The key OpenSSL resource.
     */
    protected $resource;

    /**
     * @var array The OpenSSL config array to use.
     */
    protected $config;

    /**
     * CryptoKey constructor.
     *
     * @param resource $resource The OpenSSL resource.
     * @param array $config The OpenSSL config array to use.
     * @since 0.3
     */
    public function __construct($resource, array $config = self::DEFAULT_CONFIG)
    {
        OpenSSL::isAvailable(true);
        if (!is_resource($resource)) {
            throw new RuntimeException(sprintf('Argument 1 passed to %s must be an instance of resource, %s given.',
                __FUNCTION__, gettype($resource)));
        }
        $this->resource = $resource;
        $this->config = $config;
    }

    /**
     * Destroys the CryptoKey object.
     */
    public function __destruct()
    {
        unset($this->resource);
    }

    /**
     * Gets the key string in PEM format.
     *
     * @return string|null Returns the key string in PEM format.
     * @since 0.3
     */
    public function getPEM(string $passphrase = null): string
    {
        OpenSSL::isAvailable(true);
        openssl_pkey_export($this->resource, $key, $passphrase, $this->config);
        return trim($key);
    }

    /**
     * Returns the key OpenSSL resource.
     *
     * @return resource The key OpenSSL resource.
     * @since 0.3
     */
    public function getResource()
    {
        return $this->resource;
    }

    /**
     * Saves the key to a file.
     *
     * @param string $path The path of the file to save.
     * @param string|null $passphrase The passphrase to secure the key with.
     * @return bool Returns true on success, false otherwise.
     * @since 0.3
     */
    public function save(string $path, string $passphrase = null) : bool
    {
        OpenSSL::isAvailable(true);
        return openssl_pkey_export_to_file($this->resource, $path, $passphrase, $this->config);
    }
}