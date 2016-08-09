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

namespace NorseBlue\Sikker\Asymmetric;

use NorseBlue\Sikker\OpenSSL\OpenSSL;
use NorseBlue\Sikker\OpenSSL\OpenSSLException;
use RuntimeException;

/**
 * Class CryptoKey
 *
 * @package NorseBlue\Sikker\Asymmetric
 * @since 0.3
 */
abstract class CryptoKey
{
    /**
     * @var int Unknown KeyType
     */
    const TYPE_UNKNOWN = -1;

    /**
     * @var int KeyType RSA (matches constant OPENSSL_KEYTYPE_RSA)
     */
    const TYPE_RSA = 0;

    /**
     * @var int KeyType DSA (matches constant OPENSSL_KEYTYPE_DSA)
     */
    const TYPE_DSA = 1;

    /**
     * @var int KeyType DH (matches constant OPENSSL_KEYTYPE_DH)
     */
    const TYPE_DH = 2;

    /**
     * @var int KeyType EC (matches constant OPENSSL_KEYTYPE_EC)
     */
    const TYPE_EC = 3;

    /**
     * @var array Holds the KeyType names.
     */
    const TYPES_NAMES = [
        self::TYPE_UNKNOWN => 'unknown',
        self::TYPE_RSA => 'rsa',
        self::TYPE_DSA => 'dsa',
        self::TYPE_DH => 'dh',
        self::TYPE_EC => 'ec'
    ];

    /**
     * @var array The default configuration to use by OpenSSL.
     */
    const DEFAULT_CONFIG = [
        'digest_alg' => 'sha256',
        'private_key_type' => self::TYPE_RSA,
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
        }

        if (($rtype = get_resource_type($resource)) !== 'OpenSSL key') {
            // @codeCoverageIgnoreStart
            throw new RuntimeException(sprintf('Argument 1 passed to %s must be an \'OpenSSL key\' resource, \'%s\' resource given.',
                __FUNCTION__, $rtype));
            // @codeCoverageIgnoreEnd
        }

        $this->resource = $resource;
        $this->config = $config;
        $this->loadDetails(true);
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
     * Gets the the key type as a string.
     *
     * @param int $type The type to get as string.
     * @return string Returns the key type as a string.
     * @since 0.3
     */
    public static function getTypeName(int $type) : string
    {
        if (array_key_exists($type, self::TYPES_NAMES)) {
            return self::TYPES_NAMES[$type];
        }
        return self::TYPES_NAMES[self::TYPE_UNKNOWN];
    }

    /**
     * Loads the key details from the resource.
     *
     * @param bool $throwException Whether to throw an exception on error.
     * @return bool Returns true if details have been loaded correctly, false otherwise.
     * @since 0.3
     */
    public function loadDetails($throwException = false)
    {
        $details = openssl_pkey_get_details($this->resource);
        if ($details === false) {
            // @codeCoverageIgnoreStart
            if ($throwException) {
                throw new OpenSSLException(OpenSSL::getErrors(), 'Failed to get key details.');
            }
            return false;
            // @codeCoverageIgnoreEnd
        }

        $this->details = $details;
        return true;
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
        return $this->getType() === self::TYPE_RSA;
    }

    /**
     * Verifies if the key if of type RSA.
     *
     * @return bool Returns true if key is of type RSA, false otherwise.
     * @since 0.3
     */
    public function isDSA() : bool
    {
        return $this->getType() === self::TYPE_DSA;
    }

    /**
     * Verifies if the key if of type RSA.
     *
     * @return bool Returns true if key is of type RSA, false otherwise.
     * @since 0.3
     */
    public function isDH() : bool
    {
        return $this->getType() === self::TYPE_DH;
    }

    /**
     * Verifies if the key if of type RSA.
     *
     * @return bool Returns true if key is of type RSA, false otherwise.
     * @since 0.3
     */
    public function isEC() : bool
    {
        return $this->getType() === self::TYPE_EC;
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
            case self::TYPE_RSA:
                return $this->details['rsa']['n'];
            case self::TYPE_DSA:
                return $this->details['dsa']['p'];
            case self::TYPE_DH:
                return $this->details['dh']['p'];
            default:
                // @codeCoverageIgnoreStart
                throw new CryptoKeyTypeException(sprintf('The key must be of type RSA, DSA or DH to get modulus, but key is of type \'%s\'.',
                    strtoupper(self::getTypeName($this->getType()))));
                // @codeCoverageIgnoreEnd
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