<?php
/**
 * Sikker is a PHP 7.0+ Security package that contains security related implementations.
 *
 * @package    NorseBlue\Sikker
 * @version    0.3.7
 * @author     NorseBlue
 * @license    MIT License
 * @copyright  2016 NorseBlue
 * @link       https://github.com/NorseBlue/Sikker
 */
declare(strict_types = 1);

namespace NorseBlue\Sikker\Symmetric;

/**
 * Class CipherMode
 *
 * @package NorseBlue\Sikker\Symmetric
 * @see http://php.net/manual/en/function.openssl-get-cipher-methods.php openssl_get_cipher_methods function reference.
 * @see https://www.openssl.org/docs/manmaster/apps/enc.html#SUPPORTED_CIPHERS OpenSSL supported ciphers reference.
 * @since 0.3.5
 */
abstract class CipherMode
{
    /**
     * @var int Unknown mode.
     */
    const UNKNOWN = -1;

    /**
     * @var int The EBC mode.
     */
    const ECB = 0;

    /**
     * @var int The CBC mode.
     */
    const CBC = 1;

    /**
     * @var int The CFB mode.
     */
    const CFB = 2;

    /**
     * @var int The CFB1 mode.
     */
    const CFB1 = 3;

    /**
     * @var int The CFB8 mode.
     */
    const CFB8 = 4;

    /**
     * @var int The CTR mode.
     */
    const CTR = 5;

    /**
     * @var int The OFB mode.
     */
    const OFB = 6;

    /**
     * @var int The XTS mode.
     */
    const XTS = 7;

    /**
     * @var int The CCM mode.
     */
    const CCM = 8;

    /**
     * @var int The GCM mode.
     */
    const GCM = 9;

    /**
     * @var int The WRAP mode.
     */
    const WRAP = 10;

    /**
     * @var array Holds the modes names.
     */
    const NAMES = [
        self::UNKNOWN => 'unknown',
        self::ECB => 'ecb',
        self::CBC => 'cbc',
        self::CFB => 'cfb',
        self::CFB1 => 'cfb1',
        self::CFB8 => 'cfb8',
        self::CTR => 'ctr',
        self::OFB => 'ofb',
        self::XTS => 'xts',
        self::CCM => 'ccm',
        self::GCM => 'gcm',
        self::WRAP => 'wrap'
    ];

    /**
     * Gets the cipher mode as a string.
     *
     * @param int $value The cipher mode value.
     * @return string Returns the cipher mode as string.
     * @since 0.3.5
     */
    public static function asString(int $value) : string
    {
        if (array_key_exists($value, self::NAMES)) {
            return self::NAMES[$value];
        }
        return self::NAMES[self::UNKNOWN];
    }

    /**
     * Gets the cipher mode as value.
     *
     * @param string $str The cipher mode string.
     * @return int Returns the cipher mode as value.
     * @since 0.3.5
     */
    public static function asValue(string $str) : int
    {
        $items = array_flip(self::NAMES);
        if (array_key_exists($str, $items)) {
            return $items[$str];
        }
        return self::UNKNOWN;
    }
}