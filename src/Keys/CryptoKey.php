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
use RuntimeException;

/**
 * Class CryptoKey
 *
 * @package NorseBlue\Sikker\Keys
 * @since 0.3
 */
abstract class CryptoKey
{
    /**
     * @var array The default configuration to use by OpenSSL.
     */
    const DEFAULT_CONFIG = [
        'digest_alg' => 'sha256',
        'private_key_type' => OpenSSL::KEYTYPE_RSA,
        'private_key_bits' => 2048
    ];

    /**
     * @var resource The key OpenSSL resource.
     */
    protected $resource;

    /**
     * @var array The key details.
     */
    protected $details;

    /**
     * @var array The OpenSSL config array to use.
     */
    protected $config;

    /**
     * CryptoKey constructor.
     *
     * @param resource $resource The OpenSSL key resource.
     * @param array $config The OpenSSL config array to use.
     * @since 0.3
     */
    public function __construct($resource, array $config = self::DEFAULT_CONFIG)
    {
        OpenSSL::isAvailable(true);
        if (!is_resource($resource)) {
            // @codeCoverageIgnoreStart
            throw new RuntimeException(sprintf('Argument 1 passed to %s must be a resource, %s given.',
                __FUNCTION__, gettype($resource)));
            // @codeCoverageIgnoreEnd
        } elseif (($rtype = get_resource_type($resource)) !== 'OpenSSL key') {
            // @codeCoverageIgnoreStart
            throw new RuntimeException(sprintf('Argument 1 passed to %s must be an \'OpenSSL key\' resource, \'%s\' resource given.',
                __FUNCTION__, $rtype));
            // @codeCoverageIgnoreEnd
        }
        $this->resource = $resource;
        if (($this->details = openssl_pkey_get_details($this->resource)) === false) {
            // @codeCoverageIgnoreStart
            throw new OpenSSLException(OpenSSL::getErrors(), 'Failed to get key details.');
            // @codeCoverageIgnoreEnd
        }
        $this->config = $config;
    }

    /**
     * Destroys the CryptoKey object.
     *
     * @since 0.3
     */
    public function __destruct()
    {
        unset($this->resource);
    }

    /**
     * Gets the key OpenSSL resource.
     *
     * @return resource The key OpenSSL resource.
     * @since 0.3
     */
    public function getResource()
    {
        return $this->resource;
    }

    /**
     * Gets the key details.
     *
     * @return array The key details array.
     * @since 0.3
     */
    public function getDetails() : array
    {
        return $this->details;
    }

    /**
     * Gets the config to use by OpenSSL.
     *
     * @returns array Returns the OpenSSL config array to use.
     * @since 0.3
     */
    public function getConfig() : array
    {
        return $this->config;
    }

    /**
     * Gets the number of bits.
     *
     * @returns int Returns the number of bits.
     * @since 0.3
     */
    public function getBits() : int
    {
        return $this->details['bits'];
    }

    /**
     * Gets the key type.
     *
     * @return int Returns the key type.
     * @since 0.3
     */
    public function getType() : int
    {
        return $this->details['type'];
    }

    /**
     * Verifies if the key if of type RSA.
     *
     * @return bool Returns true if key is of type RSA, false otherwise.
     * @since 0.3
     */
    public function isRSA() : bool
    {
        return $this->getType() === OpenSSL::KEYTYPE_RSA;
    }

    /**
     * Verifies if the key if of type RSA.
     *
     * @return bool Returns true if key is of type RSA, false otherwise.
     * @since 0.3
     */
    public function isDSA() : bool
    {
        return $this->getType() === OpenSSL::KEYTYPE_DSA;
    }

    /**
     * Verifies if the key if of type RSA.
     *
     * @return bool Returns true if key is of type RSA, false otherwise.
     * @since 0.3
     */
    public function isDH() : bool
    {
        return $this->getType() === OpenSSL::KEYTYPE_DH;
    }

    /**
     * Verifies if the key if of type RSA.
     *
     * @return bool Returns true if key is of type RSA, false otherwise.
     * @since 0.3
     */
    public function isEC() : bool
    {
        return $this->getType() === OpenSSL::KEYTYPE_EC;
    }

    /**
     * Gets the the key type as a string.
     *
     * @return string Returns the key type as a string.
     * @since 0.3
     */
    public function getTypeAsString() : string
    {
        switch ($this->getType()) {
            case OpenSSL::KEYTYPE_RSA:
                return 'rsa';
                break;
            case OpenSSL::KEYTYPE_DSA:
                return 'dsa';
                break;
            case OpenSSL::KEYTYPE_DH:
                return 'dh';
                break;
            case OpenSSL::KEYTYPE_EC:
                return 'ec';
                break;
            default:
                return 'unknown'; // @codeCoverageIgnore
        }
    }

    /**
     * Gets the key modulus.
     *
     * @see http://us.php.net/manual/en/function.openssl-pkey-get-details.php openssl_pkey_get_details fucntion reference.
     * @return string Returns the RSA key modulus.
     * @throws CryptoKeyTypeException when key is not of type RSA.
     * @since 0.3
     */
    public function getModulus() : string
    {
        switch ($this->getType()) {
            case OpenSSL::KEYTYPE_RSA:
                return $this->details['rsa']['n'];
                break;
            case OpenSSL::KEYTYPE_DSA:
                return $this->details['dsa']['p'];
                break;
            default:
                // @codeCoverageIgnoreStart
                throw new CryptoKeyTypeException(sprintf('The key must be of type RSA to get modulus, but key is of type \'%s\'.',
                    strtoupper($this->getTypeAsString())));
                // @codeCoverageIgnoreEnd
                break;
        }
    }

    /**
     * Gets the key string in PEM format.
     *
     * @param string $passphrase The optional passphrase to secure the key.
     * @return null|string Returns the key string in PEM format.
     * @since 0.3
     */
    abstract public function getPEM(string $passphrase = null) : string;

    /**
     * Verifies if the given key matches is a pair match.
     *
     * @param CryptoKey $pairedKey The paired key to test.
     * @return bool
     * @since 0.3
     */
    abstract public function isPairOf(CryptoKey $pairedKey) : bool;

    /**
     * Saves the key to a file.
     *
     * @param string $path The path of the file to save.
     * @param string|null $passphrase The passphrase to secure the key with.
     * @return bool Returns true on success, false otherwise.
     * @since 0.3
     */
    abstract public function save(string $path, string $passphrase = null) : bool;

    /**
     * Encrypts the given data.
     *
     * @param string $rawData The data to encrypt.
     * @return string Returns the encrypted data.
     * @since 0.3
     */
    abstract public function encrypt(string $rawData) : string;

    /**
     * Decrypts the given data.
     *
     * @param string $encryptedData The data to decrypt.
     * @return string Returns the decrypted data.
     * @since 0.3
     */
    abstract public function decrypt(string $encryptedData) : string;
}