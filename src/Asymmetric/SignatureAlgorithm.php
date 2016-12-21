<?php
/**
 * Sikker is a PHP 7.0+ Security package that contains security related implementations.
 *
 * @package    NorseBlue\Sikker
 * @version    0.3.8
 * @author     NorseBlue
 * @license    MIT License
 * @copyright  2016 NorseBlue
 * @link       https://github.com/NorseBlue/Sikker
 */
declare(strict_types = 1);

namespace NorseBlue\Sikker\Asymmetric;

/**
 * Class SignatureAlgorithm
 *
 * @package NorseBlue\Sikker\Asymmetric
 * @see http://php.net/manual/en/openssl.signature-algos.php Signature Algorithms reference.
 * @since 0.3
 */
abstract class SignatureAlgorithm
{
    /**
     * @var int Unknown KeyType
     */
    const UNKNOWN = -1;

    /**
     * @var int Signature Algorithm SHA1 (matches constant OPENSSL_ALGO_SHA1)
     */
    const SHA1 = 1;

    /**
     * @var int Signature Algorithm MD5 (matches constant OPENSSL_ALGO_MD5)
     */
    const MD5 = 2;

    /**
     * @var int Signature Algorithm MD4 (matches constant OPENSSL_ALGO_MD4)
     */
    const MD4 = 3;

    /**
     * @var int Signature Algorithm MD2 (matches constant OPENSSL_ALGO_MD2)
     */
    const MD2 = 4;

    /**
     * @var int Signature Algorithm DSS1 (matches constant OPENSSL_ALGO_DSS1)
     */
    const DSS1 = 5;

    /**
     * @var int Signature Algorithm SHA224 (matches constant OPENSSL_ALGO_SHA224)
     */
    const SHA224 = 6;

    /**
     * @var int Signature Algorithm SHA256 (matches constant OPENSSL_ALGO_SHA256)
     */
    const SHA256 = 7;

    /**
     * @var int Signature Algorithm SHA384 (matches constant OPENSSL_ALGO_SHA384)
     */
    const SHA384 = 8;

    /**
     * @var int Signature Algorithm SHA512 (matches constant OPENSSL_ALGO_SHA512)
     */
    const SHA512 = 9;

    /**
     * @var int Signature Algorithm RMD160 (matches constant OPENSSL_ALGO_RMD160)
     */
    const RMD160 = 10;

    /**
     * @var array Holds the signature algorithms names.
     */
    const NAMES = [
        self::UNKNOWN => 'unknown',
        self::SHA1 => 'sha1',
        self::MD5 => 'md5',
        self::MD4 => 'md4',
        self::MD2 => 'md2',
        self::DSS1 => 'dss1',
        self::SHA224 => 'sha224',
        self::SHA256 => 'sha256',
        self::SHA384 => 'sha384',
        self::SHA512 => 'sha512',
        self::RMD160 => 'rmd160'
    ];

    /**
     * Gets the signature algorithm as a string.
     *
     * @param int $value The signature algorithm to get as string.
     * @return string Returns the signature algorithm as a string.
     * @since 0.3
     */
    public static function toName(int $value) : string
    {
        if (array_key_exists($value, self::NAMES)) {
            return self::NAMES[$value];
        }
        return self::NAMES[self::UNKNOWN];
    }

    /**
     * Gets the signature algorithm as an integer from the name.
     *
     * @param string $name The name of the signature algorithm.
     * @return int Returns the integer value of the signature algorithm.
     * @since 0.3
     */
    public static function fromName(string $name) : int
    {
        $items = array_flip(self::NAMES);
        if (array_key_exists($name, $items)) {
            return $items[$name];
        }
        return self::UNKNOWN;
    }
}