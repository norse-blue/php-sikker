<?php
/**
 * Sikker is a PHP 7.0+ Security package that contains security related implementations.
 *
 * @package    NorseBlue\Sikker
 * @version    0.3.6
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
use NorseBlue\Sikker\Symmetric\CipherMode;

/**
 * Class CipherAES
 *
 * @package NorseBlue\Sikker\Symmetric\Ciphers
 * @since 0.3.5
 */
class CipherAES implements Cipher
{
    /**
     * @var array Holds the supported key sizes.
     */
    const SUPPORTED_KEY_SIZES = [
        KeySize::_128,
        KeySize::_192,
        KeySize::_256
    ];

    /**
     * @var array Holds the supported cipher modes.
     */
    const SUPPORTED_MODES = [
        CipherMode::ECB,
        CipherMode::CBC
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
     * @var int The bitwise disjunction between Cipher::RAW_DATA and Cipher::DISABLE_PADDING.
     */
    protected $options;

    /**
     * @var int The cipher mode (EBC or CBC).
     */
    protected $mode;

    /**
     * CipherAES constructor.
     *
     * @param int $keySize The key size to use for encryption.
     * @param string $iv The initialization vector to use.
     * @param int $options The options to use for encryption.
     * @param int $mode The mode to be used.
     * @since 0.3.5
     */
    public function __construct(
        int $keySize = KeySize::_256,
        string $iv = '',
        int $options = 0,
        int $mode = CipherMode::CBC
    ) {
        $this->setKeySize($keySize);
        $this->setIV($iv);
        $this->setOptions($options);
        $this->setMode($mode);
    }

    /**
     * Gets the key size.
     *
     * @return int Returns the cipher key size.
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
     * @return CipherAES Returns this instance for fluent interface.
     * @throws InvalidArgumentException when the key size is not supported.
     * @since 0.3.5
     */
    public function setKeySize(int $keySize) : CipherAES
    {
        if (!in_array($keySize, self::SUPPORTED_KEY_SIZES)) {
            throw new InvalidArgumentException('The given key size is not supported.');
        }
        $this->keySize = $keySize;
        return $this;
    }

    /**
     * Gets the initialization vector.
     *
     * @return string Returns the initialization vector.
     * @since 0.3.5
     */
    public function getIV() : string
    {
        return $this->iv;
    }

    /**
     * Sets the initialization vector.
     *
     * @param string $iv The new initialization vector.
     * @return CipherAES Returns this instance for fluent interface.
     * @since 0.3.5
     */
    public function setIV(string $iv) : CipherAES
    {
        $this->iv = $iv;
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
     * @return CipherAES Returns this instance for fluent interface.
     * @since 0.3.5
     */
    public function setOptions(int $options) : CipherAES
    {
        $this->options = $options;
        return $this;
    }

    /**
     * Gets the mode.
     *
     * @return int Returns the cipher mode.
     * @since 0.3.5
     */
    public function getMode() : int
    {
        return $this->mode;
    }

    /**
     * Sets the mode.
     *
     * @param int $mode The new cipher mode.
     * @return CipherAES Returns this instance for fluent interface.
     * @throws InvalidArgumentException when the mode is not supported.
     * @since 0.3.5
     */
    public function setMode(int $mode) : CipherAES
    {
        if (!in_array($mode, self::SUPPORTED_MODES)) {
            throw new InvalidArgumentException('The given mode is not supported.');
        }
        $this->mode = $mode;
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
        if (($decrypted = @openssl_decrypt($data, $this->getCipherDescription(), $password, $this->getOptions(),
                $this->getIV())) === false
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
        if (($encrypted = @openssl_encrypt($data, $this->getCipherDescription(), $password, $this->getOptions(),
                $this->getIV())) === false
        ) {
            // @codeCoverageIgnoreStart
            throw new OpenSSLException(OpenSSL::getErrors(), 'The given data could not be encrypted.');
            // @codeCoverageIgnoreEnd
        }

        return [
            $encrypted,
            StringEncoder::rawToHex($password),
            $this->getOptions(),
            $this->getIV(),
            $this->getMode()
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
        return sprintf('AES-%s-%s', $this->getKeySize(),
            strtoupper(CipherMode::asString($this->getMode())));
    }
}