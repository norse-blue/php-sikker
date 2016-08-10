<?php
/**
 * Sikker is a PHP 7.0+ Security package that contains security related implementations.
 *
 * @package    NorseBlue\Sikker
 * @version    0.3
 * @author     NorseBlue
 * @license    MIT License
 * @copyright  2016 NorseBlue
 * @link       https://github.com/NorseBlue/Sikker
 */
declare(strict_types = 1);

namespace NorseBlue\Sikker\SaltShakers;

use InvalidArgumentException;
use NorseBlue\Sikker\Tokens\TokenFactory;

/**
 * Class SaltShakerExtDES
 *
 * @package NorseBlue\Sikker\SaltShakers
 * @see http://php.net/manual/en/function.crypt.php PHP crypt function reference.
 * @uses NorseBlue\Sikker\Tokens\TokenFactory
 * @since 0.1
 */
class SaltShakerExtDES implements SaltShaker
{
    /**
     * @var string The supported salt alphabet.
     */
    const ALPHABET = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

    /**
     * @var string The salt prefix.
     */
    const PREFIX = '_';

    /**
     * @var int The salt maximum length.
     */
    const LENGTH = 4;

    /**
     * @var int The minimum number of rounds.
     */
    const MIN_ROUNDS = 1;

    /**
     * @var int The default number of rounds.
     */
    const DEFAULT_ROUNDS = 725;

    /**
     * @var int The maximum number of rounds.
     */
    const MAX_ROUNDS = 16777215;

    /**
     * @var int The number of rounds to use for hash.
     */
    protected $rounds;

    /**
     * SaltShakerExtDES constructor.
     *
     * @param int $rounds The number of rounds to use. The default is 266305.
     * @since 0.1
     */
    public function __construct(int $rounds = self::DEFAULT_ROUNDS)
    {
        $this->setRounds($rounds);
    }

    /**
     * Encodes the given rounds into the ExtDES format.
     *
     * @see http://php.net/manual/en/function.crypt.php PHP crypt function reference.
     * @param int $rounds The number of rounds to encode.
     * @return string The xtDES format encoded rounds.
     * @since 0.1
     */
    protected function encodeRounds(int $rounds) : string
    {
        $encoding = '';
        $division = $rounds;
        while ($division > 0) {
            $encoding .= substr(self::ALPHABET, $division % 64, 1);
            $division = (int) ($division / 64);
        }
        $encoding .= (strlen($encoding) < 4) ? substr(self::ALPHABET, $division % 64, 1) : '';
        return str_pad($encoding, 4, self::ALPHABET[0]);
    }

    /**
     * Gets the number of rounds.
     *
     * @return int Returns the number of rounds.
     * @since 0.1
     */
    public function getRounds() : int
    {
        return $this->rounds;
    }

    /**
     * Sets the number of rounds.
     *
     * @param int $rounds The new number of rounds.
     * @return SaltShakerExtDES Returns this instance for fluent interface.
     * @since 0.1
     */
    public function setRounds(int $rounds = null) : SaltShakerExtDES
    {
        $this->rounds = $rounds ?? self::DEFAULT_ROUNDS;
        $this->rounds = max(self::MIN_ROUNDS, min(self::MAX_ROUNDS, $this->rounds));
        return $this;
    }

    /**
     * Encodes the given salt in ExtDES format. If no salt is given a random token with max length is generated as the salt.
     *
     * @see http://php.net/manual/en/function.crypt.php PHP crypt function reference.
     * @param string|null $salt The salt to encode (up to 4 chars from the supported alphabet).
     * @return string Returns the encoded salt in ExtDES format according to {@link http://php.net/manual/en/function.crypt.php PHP crypt function reference.}
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

        return self::PREFIX.$this->encodeRounds($this->rounds).$encoded;
    }

    /**
     * Validates the given salt string.
     * Important: A valid salt is one starting with _ and having 4 chars from the alphabet ./0-9A-Za-z specifying the
     * number of rounds and another 4 chars from the alphabet ./0-9A-Za-z that represent the salt.
     *
     * @param string $salt The salt to validate.
     * @return bool Returns true if the salt is correctly ExtDES encoded, false otherwise.
     * @since 0.1
     */
    public static function isValid(string $salt) : bool
    {
        $regex = '/^_['.preg_quote(self::ALPHABET, '/').']{8}$/';
        return (bool) preg_match($regex, $salt);
    }
}