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

namespace NorseBlue\Sikker\SaltShakers;

/**
 * Interface SaltShaker
 *
 * @package NorseBlue\Sikker\SaltShakers
 * @uses NorseBlue\Sikker\Tokens\TokenFactory
 * @see http://php.net/manual/en/function.crypt.php PHP crypt function reference.
 * @see http://php.net/manual/en/function.password-hash.php PHP password_hash function reference.
 * @see http://php.net/manual/en/function.password-verify.php PHP password_verify function reference.
 * @since 0.1
 */
interface SaltShaker
{
    /**
     * Validates if the given salt is valid.
     *
     * @param string $salt The salt to validate.
     * @return bool Returns true if the given salt is valid, false otherwise.
     * @since 0.1
     */
    public static function isValid(string $salt) : bool;

    /**
     * Encodes the given salt. If no salt is given a random token is generated as the salt.
     *
     * @see http://php.net/manual/en/function.crypt.php PHP crypt function reference.
     * @param string|null $salt The salt to encode.
     * @return string Returns the encoded salt.
     * @since 0.1
     */
    public function encode(string $salt = null) : string;
}