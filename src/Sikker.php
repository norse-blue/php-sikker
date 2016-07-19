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

namespace NorseBlue\Sikker;

/**
 * Class Sikker
 *
 * @package NorseBlue\Sikker
 * @since 0.1
 */
abstract class Sikker
{
    /**
     * @var bool|null Whether OpenSSL module is available.
     */
    protected static $openSSLAvailable = null;

    /**
     * Verifies if the OpenSSL extension is loaded.
     *
     * @return bool Whether the OpenSSL extension is loaded or not.
     * @since 0.1
     * @codeCoverageIgnore Ignore as it is platform dependent.
     */
    public static function isOpenSSLAvailable()
    {
        if (self::$openSSLAvailable == null) {
            extension_loaded('openssl');
        }

        return self::$openSSLAvailable;
    }
}