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

namespace NorseBlue\Sikker\OpenSSL;

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
     * @since 0.3
     * @throws OpenSSLNotAvailableException When the extension is not loaded and throwException is true.
     */
    public static function isAvailable(bool $throwException = false) : bool
    {
        if (self::$extensionAvailable === null) {
            self::$extensionAvailable = extension_loaded('openssl');
        }

        if (!self::$extensionAvailable && $throwException) {
            throw new OpenSSLNotAvailableException('OpenSSL extension is not available.');  // @codeCoverageIgnore
        }

        return self::$extensionAvailable;
    }

    /**
     * Gets the OpenSSL configuration.
     *
     * @see http://php.net/manual/en/openssl.installation.php PHP OpenSSL Installation
     * @return string Returns the OpenSSL configuration.
     * @since 0.3
     */
    public static function getConfiguration()
    {
        OpenSSL::isAvailable(true);
        if ($openSSLConf = getenv('OPENSSL_CONF') === false) {
            $openSSLConf = getenv('SSLEAY_CONF');       // @codeCoverageIgnore
        }

        return $openSSLConf;
    }

    /**
     * Gets all OpenSSL errors.
     *
     * @return array Returns an array containing all openssl errors at the moment.
     * @since 0.3
     */
    public static function getErrors() : array
    {
        OpenSSL::isAvailable(true);
        $errors = [];
        while ($error = openssl_error_string()) {
            $errors[] = $error;     // @codeCoverageIgnore
        }

        return $errors;
    }
}