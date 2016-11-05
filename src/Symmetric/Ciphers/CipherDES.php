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
use NorseBlue\Sikker\Symmetric\CipherMethod;
use NorseBlue\Sikker\Symmetric\CipherMode;

/**
 * Class CipherDES
 *
 * @package NorseBlue\Sikker\Symmetric\Ciphers
 * @since 0.3.5
 */
class CipherDES implements Cipher
{
    /**
     * @var int Mode DES.
     */
    const METHOD_SIMPLE = 0;

    /**
     * @var int Mode DES-EDE.
     */
    const METHOD_TRIPLE_2KEY = 1;

    /**
     * @var int Mode DES-EDE3.
     */
    const METHOD_TRIPLE_3KEY = 2;

    /**
     * @var int Mode DESX.
     */
    const METHOD_X = 3;

    /**
     * @var array Holds the supported methods.
     */
    const SUPPORTED_METHODS = [
        self::METHOD_SIMPLE => CipherMethod::DES,
        self::METHOD_TRIPLE_2KEY => CipherMethod::DES3_2K,
        self::METHOD_TRIPLE_3KEY => CipherMethod::DES3_3K,
        self::METHOD_X => CipherMethod::DESX
    ];

    /**
     * @var array Holds the supported modes.
     */
    const SUPPORTED_MODES = [
        CipherMode::ECB,
        CipherMode::CBC
    ];

    /**
     * @var int The method to use.
     */
    protected $method;

    /**
     * @var string The initialization vector to use.
     */
    protected $iv;

    /**
     * @var int The bitwise disjunction between Cipher::RAW_DATA and Cipher::DISABLE_PADDING
     */
    protected $options;

    /**
     * @var@var int The cipher mode (EBC or CBC).
     */
    protected $mode;

    /**
     * CipherDES constructor.
     *
     * @param int $method The cipher method to use.
     * @param string $iv The initialization vector to use.
     * @param int $options The options to use for encryption.
     * @param int $mode The mode to be used.
     * @since 0.3.5
     */
    public function __construct(
        int $method = self::METHOD_TRIPLE_3KEY,
        string $iv = '',
        int $options = 0,
        int $mode = CipherMode::CBC
    ) {
        $this->setMethod($method);
        $this->setIV($iv);
        $this->setOptions($options);
        $this->setMode($mode);
    }

    /**
     * Gets the method.
     *
     * @return int Returns the method.
     * @since 0.3.5
     */
    public function getMethod() : int
    {
        return $this->method;
    }

    /**
     * Sets the method.
     *
     * @param int $method The new method.
     * @return CipherDES Returns this instance for fluent interface.
     * @throws InvalidArgumentException when the method is not supported.
     * @since 0.3.5
     */
    public function setMethod(int $method) : CipherDES
    {
        if (!array_key_exists($method, self::SUPPORTED_METHODS)) {
            throw new InvalidArgumentException('The given method is not supported.');
        }
        $this->method = $method;
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
     * @return CipherDES Returns this instance for fluent interface.
     * @since 0.3.5
     */
    public function setIV(string $iv) : CipherDES
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
     * @return CipherDES Returns this instance for fluent interface.
     * @since 0.3.5
     */
    public function setOptions(int $options) : CipherDES
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
     * @return CipherDES Returns this instance for fluent interface.
     * @throws InvalidArgumentException when the mode is not supported.
     * @since 0.3.5
     */
    public function setMode(int $mode) : CipherDES
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
            $this->getMethod()
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
        return sprintf('%s-%s', self::SUPPORTED_METHODS[$this->getMethod()],
            strtoupper(CipherMode::asString($this->getMode())));
    }
}