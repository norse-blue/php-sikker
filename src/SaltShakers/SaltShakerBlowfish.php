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
 * Class SaltShakerBlowfish
 *
 * @package NorseBlue\Sikker\SaltShakers
 * @see http://php.net/manual/en/function.crypt.php PHP crypt function reference.
 * @see http://php.net/security/crypt_blowfish.php CRYPT_BLOWFISH security fix details.
 * @uses NorseBlue\Sikker\Tokens\TokenFactory
 * @since 0.1
 */
class SaltShakerBlowfish implements SaltShaker
{
    /**
     * @var string The supported salt alphabet.
     */
    const ALPHABET = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

    /**
     * @var string Blowfish salt mode A prefix.
     */
    const MODE_A = '$2a$';

    /**
     * @var string Blowfish salt mode X prefix.
     */
    const MODE_X = '$2x$';

    /**
     * @var string Blowfish salt mode Y prefix.
     */
    const MODE_Y = '$2y$';

    /**
     * @var string The Blowfish salt postfix.
     */
    const POSTFIX = '$';

    /**
     * @var string The cost postfix.
     */
    const COST_POSTFIX = '$';

    /**
     * @var int The salt length (not counting prefix). The salt must always be this length.
     */
    const LENGTH = 21;

    /**
     * @var string The default Blowfish mode.
     */
    const DEFAULT_MODE = self::MODE_Y;

    /**
     * @var int The minimum supported cost.
     */
    const MIN_COST = 4;

    /**
     * @var int The default cost.
     */
    const DEFAULT_COST = 10;

    /**
     * @var int The maximum supported cost.
     */
    const MAX_COST = 31;

    /**
     * @var string The Blowfish mode used.
     */
    protected $mode;

    /**
     * @var int The cost to use for hash.
     */
    protected $cost;

    /**
     * SaltShakerBlowfish constructor.
     *
     * @param string $mode The mode to use. The default is $2y$.
     * @param int $cost The cost to use. The default is 10.
     * @since 0.1
     */
    public function __construct(string $mode = self::DEFAULT_MODE, $cost = self::DEFAULT_COST)
    {
        $this->setMode($mode);
        $this->setCost($cost);
    }

    /**
     * Gets the mode.
     *
     * @return string Returns the mode.
     * @since 0.1
     */
    public function getMode() : string
    {
        return $this->mode;
    }

    /**
     * Sets the mode.
     *
     * @param string $mode The new mode.
     * @return SaltShakerBlowfish Returns this instance for fluent interface.
     * @since 0.1
     */
    public function setMode(string $mode = null) : SaltShakerBlowfish
    {
        if ($mode === null || !in_array($mode, [self::MODE_A, self::MODE_X, self::MODE_Y])) {
            $this->mode = self::DEFAULT_MODE;
        } else {
            $this->mode = $mode;
        }
        return $this;
    }

    /**
     * Gets the cost.
     *
     * @return int Returns the cost.
     * @since 0.1
     */
    public function getCost() : int
    {
        return $this->cost;
    }

    /**
     * Sets the cost.
     *
     * @param int $cost The new cost.
     * @return SaltShakerBlowfish Returns this instance for fluent interface.
     * @since 0.1
     */
    public function setCost(int $cost = null) : SaltShakerBlowfish
    {
        $this->cost = $cost ?? self::DEFAULT_COST;
        $this->cost = max(self::MIN_COST, min(self::MAX_COST, $this->cost));
        return $this;
    }

    /**
     * Encodes the given salt in Blowfish format. If no salt is given a random token with max length is generated as the salt.
     *
     * @see http://php.net/manual/en/function.crypt.php PHP crypt function reference.
     * @param string|null $salt The salt to encode (up to 22 chars).
     * @return string Returns the encoded salt in Blowfish format according to {@link http://php.net/manual/en/function.crypt.php PHP crypt function reference.}
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

        $cost = sprintf('%02d', $this->cost).self::COST_POSTFIX;
        return $this->mode.$cost.$encoded.self::POSTFIX;
    }

    /**
     * Validates the given salt string.
     * Important: A valid salt is one with 33 chars of length. Starting with $2a$, $2x$ or $2y$ following with
     * two digits in the range 04-31 then a $ and a 21 long string from the alphabet ./0-9A-Za-z and ending with a $.
     *
     * @param string $salt The salt to validate.
     * @return bool Returns true if the salt is correctly Blowfish encoded, false otherwise.
     * @since 0.1
     */
    public static function isValid(string $salt) : bool
    {
        $regex = '/^\$2[axy]\$(?:0[4-9]|[1-2][0-9]|3[0-1])\$['.preg_quote(self::ALPHABET, '/').']{21}\$$/';
        return (bool) preg_match($regex, $salt);
    }
}