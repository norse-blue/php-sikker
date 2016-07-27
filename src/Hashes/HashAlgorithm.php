<?php
/**
 * Sikker is a PHP 7.0+ Security package that contains security related implementations.
 *
 * @package    NorseBlue\Sikker
 * @version    0.1.1
 * @author     NorseBlue
 * @license    MIT License
 * @copyright  2016 NorseBlue
 * @link       https://github.com/NorseBlue/Sikker
 */
declare(strict_types = 1);

namespace NorseBlue\Sikker\Hashes;

/**
 * Class HashAlgorithm
 *
 * @package NorseBlue\Sikker\Hashes
 * @since 0.1
 */
abstract class HashAlgorithm
{
    /**
     * @var string MD2 hash algorithm.
     */
    const MD2 = 'md2';

    /**
     * @var string MD4 hash algorithm.
     */
    const MD4 = 'md4';

    /**
     * @var string MD5 hash algorithm.
     */
    const MD5 = 'md5';

    /**
     * @var string SHA1 hash algorithm.
     */
    const SHA1 = 'sha1';

    /**
     * @var string SHA224 hash algorithm.
     */
    const SHA224 = 'sha224';

    /**
     * @var string SHA256 hash algorithm.
     */
    const SHA256 = 'sha256';

    /**
     * @var string SHA384 hash algorithm.
     */
    const SHA384 = 'sha384';

    /**
     * @var string SHA512 hash algorithm.
     */
    const SHA512 = 'sha512';

    /**
     * @var string RIPEMD128 hash algorithm.
     */
    const RIPEMD128 = 'ripemd128';

    /**
     * @var string RIPEMD160 hash algorithm.
     */
    const RIPEMD160 = 'ripemd160';

    /**
     * @var string RIPEMD256 hash algorithm.
     */
    const RIPEMD256 = 'ripemd256';

    /**
     * @var string RIPEMD320 hash algorithm.
     */
    const RIPEMD320 = 'ripemd320';

    /**
     * @var string WHIRLPOOL hash algorithm.
     */
    const WHIRLPOOL = 'whirlpool';

    /**
     * @var string TIGER128,3 hash algorithm.
     */
    const TIGER128_3 = 'tiger128,3';

    /**
     * @var string TIGER 160,3 hash algorithm.
     */
    const TIGER160_3 = 'tiger160,3';

    /**
     * @var string TIGER192,3 hash algorithm.
     */
    const TIGER192_3 = 'tiger192,3';

    /**
     * @var string TIGER128,4 hash algorithm.
     */
    const TIGER128_4 = 'tiger128,4';

    /**
     * @var string TIGER160,4 hash algorithm.
     */
    const TIGER160_4 = 'tiger160,4';

    /**
     * @var string TIGER 192,4 hash algorithm.
     */
    const TIGER192_4 = 'tiger192,4';

    /**
     * @var string SNEFRU hash algorithm.
     */
    const SNEFRU = 'snefru';

    /**
     * @var string SNEFRU256 hash algorithm.
     */
    const SNEFRU256 = 'snefru256';

    /**
     * @var string GOST hash algorithm.
     */
    const GOST = 'gost';

    /**
     * @var string ADLER32 hash algorithm.
     */
    const ADLER32 = 'adler32';

    /**
     * @var string CRC32 hash algorithm.
     */
    const CRC32 = 'crc32';

    /**
     * @var string CRC32B hash algorithm.
     */
    const CRC32B = 'crc32b';

    /**
     * @var string FNV132 hash algorithm.
     */
    const FNV132 = 'fnv132';

    /**
     * @var string FNV164 hash algorithm.
     */
    const FNV164 = 'fnv164';

    /**
     * @var string JOAAT hash algorithm.
     */
    const JOAAT = 'joaat';

    /**
     * @var string HAVAL128,3 hash algorithm.
     */
    const HAVAL128_3 = 'haval128,3';

    /**
     * @var string HAVAL160,3 hash algorithm.
     */
    const HAVAL160_3 = 'haval160,3';

    /**
     * @var string HAVAL192,3 hash algorithm.
     */
    const HAVAL192_3 = 'haval192,3';

    /**
     * @var string HAVAL224,3 hash algorithm.
     */
    const HAVAL224_3 = 'haval224,3';

    /**
     * @var string HAVAL256,3 hash algorithm.
     */
    const HAVAL256_3 = 'haval256,3';

    /**
     * @var string HAVAL128,4 hash algorithm.
     */
    const HAVAL128_4 = 'haval128,4';

    /**
     * @var string HAVAL160,4 hash algorithm.
     */
    const HAVAL160_4 = 'haval160,4';

    /**
     * @var string HAVAL192,4 hash algorithm.
     */
    const HAVAL192_4 = 'haval192,4';

    /**
     * @var string HAVAL224,4 hash algorithm.
     */
    const HAVAL224_4 = 'haval224,4';

    /**
     * @var string HAVAL256,4 hash algorithm.
     */
    const HAVAL256_4 = 'haval256,4';

    /**
     * @var string HAVAL128,5 hash algorithm.
     */
    const HAVAL128_5 = 'haval128,5';

    /**
     * @var string HAVAL160,5 hash algorithm.
     */
    const HAVAL160_5 = 'haval160,5';

    /**
     * @var string HAVAL192,5 hash algorithm.
     */
    const HAVAL192_5 = 'haval192,5';

    /**
     * @var string HAVAL224,5 hash algorithm.
     */
    const HAVAL224_5 = 'haval224,5';
    
    /**
     * @var string HAVAL256,5 hash algorithm.
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