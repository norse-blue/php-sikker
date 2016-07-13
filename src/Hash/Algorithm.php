<?php
/**
 * Sikker is a PHP 7.0+ Security package that contains security related implementations.
 *
 * @package    NorseBlue\Sikker
 * @version    0.1
 * @author     NorseBlue
 * @license    MIT License
 * @copyright  2016 NorseBlue
 * @link       https://github.com/NorseBlue/Sikker
 */
declare(strict_types = 1);

namespace NorseBlue\Sikker\Hash;

/**
 * Class Hasher
 *
 * @package NorseBlue\Sikker\Hash
 * @since 0.1
 */
abstract class Algorithm
{
    /**
     * @var string MD2 hash type.
     */
    const MD2 = 'md2';
    /**
     * @var string MD4 hash type.
     */
    const MD4 = 'md4';
    /**
     * @var string MD5 hash type.
     */
    const MD5 = 'md5';
    /**
     * @var string SHA1 hash type.
     */
    const SHA1 = 'sha1';
    /**
     * @var string SHA224 hash type.
     */
    const SHA224 = 'sha224';
    /**
     * @var string SHA256 hash type.
     */
    const SHA256 = 'sha256';
    /**
     * @var string SHA384 hash type.
     */
    const SHA384 = 'sha384';
    /**
     * @var string SHA512 hash type.
     */
    const SHA512 = 'sha512';
    /**
     * @var string
     */
    const RIPEMD128 = 'ripemd128';
    /**
     * @var string
     */
    const RIPEMD160 = 'ripemd160';
    /**
     * @var string
     */
    const RIPEMD256 = 'ripemd256';
    /**
     * @var string
     */
    const RIPEMD320 = 'ripemd320';
    /**
     * @var string
     */
    const WHIRLPOOL = 'whirlpool';
    /**
     * @var string
     */
    const TIGER128_3 = 'tiger128,3';
    /**
     * @var string
     */
    const TIGER160_3 = 'tiger160,3';
    /**
     * @var string
     */
    const TIGER192_3 = 'tiger192,3';
    /**
     * @var string
     */
    const TIGER128_4 = 'tiger128,4';
    /**
     * @var string
     */
    const TIGER160_4 = 'tiger160,4';
    /**
     * @var string
     */
    const TIGER192_4 = 'tiger192,4';
    /**
     * @var string
     */
    const SNEFRU = 'snefru';
    /**
     * @var string
     */
    const SNEFRU256 = 'snefru256';
    /**
     * @var string
     */
    const GOST = 'gost';
    /**
     * @var string
     */
    const ADLER32 = 'adler32';
    /**
     * @var string
     */
    const CRC32 = 'crc32';
    /**
     * @var string
     */
    const CRC32B = 'crc32b';
    /**
     * @var string
     */
    const FNV132 = 'fnv132';
    /**
     * @var string
     */
    const FNV164 = 'fnv164';
    /**
     * @var string
     */
    const JOAAT = 'joaat';
    /**
     * @var string
     */
    const HAVAL128_3 = 'haval128,3';
    /**
     * @var string
     */
    const HAVAL160_3 = 'haval160,3';
    /**
     * @var string
     */
    const HAVAL192_3 = 'haval192,3';
    /**
     * @var string
     */
    const HAVAL224_3 = 'haval224,3';
    /**
     * @var string
     */
    const HAVAL256_3 = 'haval256,3';
    /**
     * @var string
     */
    const HAVAL128_4 = 'haval128,4';
    /**
     * @var string
     */
    const HAVAL160_4 = 'haval160,4';
    /**
     * @var string
     */
    const HAVAL192_4 = 'haval192,4';
    /**
     * @var string
     */
    const HAVAL224_4 = 'haval224,4';
    /**
     * @var string
     */
    const HAVAL256_4 = 'haval256,4';
    /**
     * @var string
     */
    const HAVAL128_5 = 'haval128,5';
    /**
     * @var string
     */
    const HAVAL160_5 = 'haval160,5';
    /**
     * @var string
     */
    const HAVAL192_5 = 'haval192,5';
    /**
     * @var string
     */
    const HAVAL224_5 = 'haval224,5';
    /**
     * @var string
     */
    const HAVAL256_5 = 'haval256,5';
    /**
     * @var null|array List of the available algorithms or null if not initialized.
     */
    private static $availableAlgorithms = null;

    /**
     * Verifies if the given algorithm is available.
     *
     * @param string $algorithm The algorithm to check for.
     * @return bool Returns true if the algorithm is available, false otherwise.
     * @since 0.1
     */
    public static function isAvailable(string $algorithm) : bool
    {
        return (in_array($algorithm, self::allAvailable()));
    }

    /**
     * Gets all the supported hash algorithms.
     *
     * @return array Returns a numerically indexed array containing the list of supported hashing algorithms.
     * @since 0.1
     */
    public static function allAvailable() : array
    {
        if (self::$availableAlgorithms === null) {
            self::$availableAlgorithms = hash_algos();
        }

        return self::$availableAlgorithms;
    }
}