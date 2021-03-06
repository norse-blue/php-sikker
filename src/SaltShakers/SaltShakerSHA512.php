<?php
/**
 * Sikker is a PHP 7.0+ Security package that contains security related implementations.
 *
 * @package    NorseBlue\Sikker
 * @version    0.3.8
 * @author     NorseBlue
 * @license    MIT License
 * @copyright  2016 NorseBlue
 * @link       https://github.com/NorseBlue/Sikker
 */
declare(strict_types = 1);

namespace NorseBlue\Sikker\SaltShakers;

use NorseBlue\Sikker\Tokens\Tokenizer;

/**
 * Class SaltShakerSHA512
 *
 * @package NorseBlue\Sikker\SaltShakers
 * @see http://php.net/manual/en/function.crypt.php PHP crypt function reference.
 * @uses NorseBlue\Sikker\Tokens\Tokenizer
 * @since 0.1
 */
class SaltShakerSHA512 implements SaltShaker
{
    /**
     * @var string SHA512 salt prefix.
     */
    const PREFIX = '$6$';

    /**
     * @var string SHA512 salt rounds opening.
     */
    const ROUNDS_OPEN = 'rounds=';

    /**
     * @var string SHA512 salt rounds closing.
     */
    const ROUNDS_CLOSE = '$';

    /**
     * @var string SHA512 salt postfix.
     */
    const POSTFIX = '$';

    /**
     * @var int The maximum salt length (not counting prefix and postfix).
     */
    const MAX_LENGTH = 16;

    /**
     * @var int The minimum supported number of rounds.
     */
    const MIN_ROUNDS = 1000;

    /**
     * @var int The default number of rounds.
     */
    const DEFAULT_ROUNDS = 5000;

    /**
     * @var int The maximum supported number of rounds.
     */
    const MAX_ROUNDS = 999999999;

    /**
     * @var int The number of rounds to use for hash.
     */
    protected $rounds;

    /**
     * SaltShakerSHA512 constructor.
     *
     * @param int $rounds The number of rounds to use. The default is 5000.
     * @since 0.1
     */
    public function __construct(int $rounds = self::DEFAULT_ROUNDS)
    {
        $this->setRounds($rounds);
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
     * @return SaltShakerSHA512 Returns this instance for fluent interface.
     * @since 0.1
     */
    public function setRounds(int $rounds = null) : SaltShakerSHA512
    {
        $this->rounds = $rounds ?? self::DEFAULT_ROUNDS;
        $this->rounds = max(self::MIN_ROUNDS, min(self::MAX_ROUNDS, $this->rounds));
        return $this;
    }

    /**
     * Encodes the given salt in SHA512 format. If no salt is given a random token with max length is generated as the salt.
     *
     * @see http://php.net/manual/en/function.crypt.php PHP crypt function reference.
     * @param string|null $salt The salt to encode (up to 16 chars). The salt will also be truncated at the first $ found.
     * @return string Returns the encoded salt in SHA512 format according to {@link http://php.net/manual/en/function.crypt.php PHP crypt function reference.}
     * @since 0.1
     */
    public function encode(string $salt = null) : string
    {
        if ($salt === null) {
            $encoded = Tokenizer::generate(self::MAX_LENGTH);
        } else {
            $encoded = substr($salt, 0, min(self::MAX_LENGTH, strlen($salt)));
        }

        if (($dollar = strpos($encoded, '$')) !== false) {
            $encoded = substr($encoded, 0, $dollar);
        }

        $rounds = self::ROUNDS_OPEN.$this->rounds.self::ROUNDS_CLOSE;

        return self::PREFIX.$rounds.$encoded.self::POSTFIX;
    }

    /**
     * Validates the given salt string.
     * Important: A valid salt is one starting with $5$ having an optional rounds=<N>$ mid part followed by a 16 long
     * string and ending with $. The rounds value must be between 1000 and 999999999.
     *
     * @param string $salt The salt to validate.
     * @return bool Returns true if the salt is correctly SHA512 encoded, false otherwise.
     * @since 0.1
     */
    public static function isValid(string $salt) : bool
    {
        $matches = [];
        $regex = '/^\$6\$(?:rounds=(?<rounds>\d{4,9})\$)?.{16}\$$/';
        if (!(bool) preg_match($regex, $salt, $matches)) {
            return false;
        }

        $rounds = intval($matches['rounds']);
        return ($rounds >= self::MIN_ROUNDS && $rounds <= self::MAX_ROUNDS);
    }
}