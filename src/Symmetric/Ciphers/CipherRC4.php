<?php
/**
 * Sikker is a PHP 7.0+ Security package that contains security related implementations.
 *
 * @package    NorseBlue\Sikker
 * @version    0.3.5
 * @author     NorseBlue
 * @license    MIT License
 * @copyright  2016 NorseBlue
 * @link       https://github.com/NorseBlue/Sikker
 */
declare(strict_types = 1);

namespace NorseBlue\Sikker\Symmetric\Ciphers;

use InvalidArgumentException;
use NorseBlue\Sikker\OpenSSL\OpenSSL;
use NorseBlue\Sikker\OpenSSL\OpenSSLException;
use NorseBlue\Sikker\StringEncoder;
use NorseBlue\Sikker\Symmetric\KeySize;

/**
 * Class CipherRC4
 *
 * @package NorseBlue\Sikker\Symmetric\Ciphers
 * @since 0.3.5
 */
class CipherRC4 implements Cipher
{
    /**
     * @var array Holds the supported key sizes.
     */
    const SUPPORTED_KEY_SIZES = [
        KeySize::_40,
        KeySize::_64,
        KeySize::_128
    ];

    /**
     * @var int The key size to use.
     */
    protected $keySize;

    /**
     * @var string The initialization vector to use.
     */
    protected $iv;

    /**
     * @var int The bitwise disjunction between Cipher::RAW_DATA and Cipher::DISABLE_PADDING
     */
    protected $options;

    /**
     * CipherRC4 constructor.
     *
     * @param int $keySize The key size to use.
     * @param int $options The options to use for encryption.
     * @since 0.3.5
     */
    public function __construct(
        int $keySize = KeySize::_128,
        int $options = 0
    ) {
        $this->setKeySize($keySize);
        $this->setOptions($options);
    }

    /**
     * Gets the key size.
     *
     * @return int Returns the key size.
     * @since 0.3.5
     */
    public function getKeySize() : int
    {
        return $this->keySize;
    }

    /**
     * Sets the key size.
     *
     * @param int $keySize The new key size.
     * @return CipherRC4 Returns this instance for fluent interface.
     * @throws InvalidArgumentException when the key size is not supported.
     * @since 0.3.5
     */
    public function setKeySize(int $keySize) : CipherRC4
    {
        if (!in_array($keySize, self::SUPPORTED_KEY_SIZES)) {
            throw new InvalidArgumentException('The given key size is not supported.');
        }
        $this->keySize = $keySize;
        return $this;
    }

    /**
     * Gets the options.
     *
     * @return int Returns the options.
     * @since 0.3.5
     */
    public function getOptions() : int
    {
        return $this->options;
    }

    /**
     * Sets the options.
     *
     * @param int $options The new options.
     * @return CipherRC4 Returns this instance for fluent interface.
     * @since 0.3.5
     */
    public function setOptions(int $options) : CipherRC4
    {
        $this->options = $options;
        return $this;
    }

    /**
     * Decrypts the given data with the given password.
     *
     * @param string $data The data to decrypt. Can be raw or base64 encoded.
     * @param string $password The password to decrypt data with.
     * @return string Returns the decrypted data.
     * @see http://php.net/manual/en/function.openssl-decrypt.php openssl_decrypt function reference
     * @throws OpenSSLException when the cipher cannot decrypt the data.
     * @since 0.3.5
     */
    public function decrypt(string $data, string $password) : string
    {
        OpenSSL::resetErrors();
        if (($decrypted = @openssl_decrypt($data, $this->getCipherDescription(), $password,
                $this->getOptions())) === false
        ) {
            // @codeCoverageIgnoreStart
            throw new OpenSSLException(OpenSSL::getErrors(), 'The given data could not be decrypted.');
            // @codeCoverageIgnoreEnd
        }

        return $decrypted;
    }

    /**
     * Encrypts the given data with the given password.
     *
     * @param string $data The data to encrypt.
     * @param string $password The password to encrypt data with.
     * @return array Returns an array containing the encrypted data and some information like the IV if used.
     *                  0 => [string] encrypted data
     *                  1 => [string] password as hex string
     *                  2 => [int] options used (the bitwise disjunction value)
     *                  3 => [string] iv used for encryption
     *                  4 => [int] cipher mode used
     * @see http://php.net/manual/en/function.openssl-encrypt.php openssl_encrypt function reference
     * @throws OpenSSLException when the cipher cannot encrypt the data.
     * @since 0.3.5
     */
    public function encrypt(string $data, string $password) : array
    {
        OpenSSL::resetErrors();
        if (($encrypted = @openssl_encrypt($data, $this->getCipherDescription(), $password,
                $this->getOptions())) === false
        ) {
            // @codeCoverageIgnoreStart
            throw new OpenSSLException(OpenSSL::getErrors(), 'The given data could not be encrypted.');
            // @codeCoverageIgnoreEnd
        }

        return [
            $encrypted,
            StringEncoder::rawToHex($password),
            $this->getOptions(),
            '',
            $this->getKeySize()
        ];
    }

    /**
     * Gets the cipher description.
     *
     * @return string Returns the cipher description string.
     * @since 0.3.5
     */
    public function getCipherDescription() : string
    {
        if ($this->getKeySize() == KeySize::_128) {
            return 'RC4';
        }

        return sprintf('RC4-%s', $this->getKeySize());
    }
}