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

namespace NorseBlue\Sikker\Passwords\SaltShakers;

use NorseBlue\Sikker\Tokens\TokenFactory;

/**
 * Class SaltShakerMD5
 *
 * @package NorseBlue\Sikker\Passwords\SaltShakers
 * @see http://php.net/manual/en/function.crypt.php PHP crypt function reference.
 * @uses NorseBlue\Sikker\Tokens\TokenFactory
 * @since 0.1
 */
class SaltShakerMD5 implements SaltShaker
{
    /**
     * @var string MD5 salt prefix.
     */
    const PREFIX = '$1$';

    /**
     * @var string MD5 salt postfix.
     */
    const POSTFIX = '$';

    /**
     * @var int The maximum salt length (not counting prefix and postfix).
     */
    const MAX_LENGTH = 8;

    /**
     * SaltShakerMD5 constructor.
     *
     * @since 0.1
     */
    public function __construct()
    {
    }

    /**
     * Encodes the given salt in MD5 format. If no salt is given a random token with max length is generated as the salt.
     *
     * @see http://php.net/manual/en/function.crypt.php PHP crypt function reference.
     * @param string|null $salt The salt to encode (up to 8 chars). The salt will also be truncated at the first $ found.
     * @return string Returns the encoded salt in MD5 format according to {@link http://php.net/manual/en/function.crypt.php PHP crypt function reference.}
     * @since 0.1
     */
    public function encode(string $salt = null) : string
    {
        if ($salt === null) {
            $tokenFactory = new TokenFactory(self::MAX_LENGTH);
            $encoded = $tokenFactory->forgeToken();
        } else {
            $encoded = substr($salt, 0, min(self::MAX_LENGTH, strlen($salt)));
        }

        if (($dollar = strpos($encoded, '$')) !== false) {
            $encoded = substr($encoded, 0, $dollar);
        }

        return self::PREFIX.$encoded.self::POSTFIX;
    }

    /**
     * Validates the given salt string.
     * Important: A valid salt is one with 12 chars of length starting with $1$ and ending with $.
     *
     * @param string $salt The salt to validate.
     * @return bool Returns true if the salt is correctly MD5 encoded, false otherwise.
     * @since 0.1
     */
    public static function isValid(string $salt) : bool
    {
        $regex = '/^\$1\$.{8}\$$/';
        return (bool) preg_match($regex, $salt);
    }
}