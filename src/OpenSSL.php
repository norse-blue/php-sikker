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

namespace NorseBlue\Sikker;

/**
 * Class OpenSSL
 *
 * @package NorseBlue\Sikker
 * @since 0.3
 */
class OpenSSL
{
    /**
     * @var bool|null Whether OpenSSL extension is available.
     */
    protected static $extensionAvailable = null;

    /**
     * Verifies if the OpenSSL extension is loaded.
     *
     * @param bool $throwException Whether to throw an exception is the extension is not loaded.
     * @return bool Whether the OpenSSL extension is loaded or not.
     * @since 0.1
     * @throws OpenSSLNotAvailableException When the extension is not loaded and throwException is true.
     * @codeCoverageIgnore Ignore as it is platform dependent.
     */
    public static function isAvailable(bool $throwException = false) : bool
    {
        if (self::$extensionAvailable == null) {
            self::$extensionAvailable = extension_loaded('openssl');
        }

        if (!self::$extensionAvailable && $throwException) {
            throw new OpenSSLNotAvailableException('OpenSSL extension is not available.');
        }

        return self::$extensionAvailable;
    }

    /**
     * Gets all OpenSSL errors.
     *
     * @return array Returns an array containing all openssl errors at the moment.
     */
    public static function getErrors() : array
    {
        OpenSSL::isAvailable(true);

        $errors = [];
        while ($error = openssl_error_string()) {
            $errors[] = $error;
        }

        return $errors;
    }
}