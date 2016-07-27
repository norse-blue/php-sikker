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

namespace NorseBlue\Sikker\Passwords\SaltShakers;

use InvalidArgumentException;
use NorseBlue\Sikker\Tokens\TokenFactory;

/**
 * Class SaltShakerStdDES
 *
 * @package NorseBlue\Sikker\Passwords\SaltShakers
 * @see http://php.net/manual/en/function.crypt.php PHP crypt function reference.
 * @uses NorseBlue\Sikker\Tokens\TokenFactory
 * @since 0.1
 */
class SaltShakerStdDES implements SaltShaker
{
    /**
     * @var string The supported salt alphabet.
     */
    const ALPHABET = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

    /**
     * @var int The salt length.
     */
    const LENGTH = 2;

    /**
     * SaltShakerStdDES constructor.
     *
     * @since 0.1
     */
    public function __construct()
    {
    }

    /**
     * Encodes the given salt in StdDES format. If no salt is given a random token with max length is generated as the salt.
     *
     * @see http://php.net/manual/en/function.crypt.php PHP crypt function reference.
     * @param string|null $salt The salt to encode (up to 2 chars from the supported alphabet).
     * @return string Returns the encoded salt in StdDES format according to {@link http://php.net/manual/en/function.crypt.php PHP crypt function reference.}
     * @since 0.1
     */
    public function encode(string $salt = null) : string
    {
        if ($salt === null) {
            $tokenFactory = new TokenFactory(self::LENGTH, self::ALPHABET);
            $encoded = $tokenFactory->forgeToken();
        } else {
            if (preg_match('/[^'.preg_quote(self::ALPHABET, '/').']/', $salt) !== 0) {
                throw new InvalidArgumentException('The given salt has characters that are not part of the supported alphabet.');
            }

            if (($len = strlen($salt)) < self::LENGTH) {
                $tokenFactory = new TokenFactory(self::LENGTH - $len, self::ALPHABET);
                $encoded = $salt.$tokenFactory->forgeToken();
            } else {
                $encoded = substr($salt, 0, min(self::LENGTH, $len));
            }
        }

        return $encoded;
    }

    /**
     * Validates the given salt string.
     * Important: A valid salt is one with 2 chars of length from the alphabet ./0-9A-Za-z.
     *
     * @param string $salt The salt to validate.
     * @return bool Returns true if the salt is correctly StdDES encoded, false otherwise.
     * @since 0.1
     */
    public static function isValid(string $salt) : bool
    {
        $regex = '/^['.preg_quote(self::ALPHABET, '/').']{2}$/';
        return (bool) preg_match($regex, $salt);
    }
}