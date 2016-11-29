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

namespace NorseBlue\Sikker\Tokens;

use NorseBlue\Sikker\StringEncoder;

/**
 * Class Tokenizer
 *
 * @package NorseBlue\Sikker\Tokens
 * @since 0.1
 */
class Tokenizer
{
    /**
     * @var int The default length of the tokens to be generated.
     */
    const DEFAULT_LENGTH = 32;

    /**
     * @var string The default alphabet that is used by the Tokenizer (alphanumeric characters).
     */
    const DEFAULT_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

    /**
     * @var int The length of the token to generate.
     */
    protected $length;

    /**
     * @var string The alphabet to be used by the Tokenizer.
     */
    protected $alphabet;

    /**
     * @var Tokenizer A static tokenizer to optimize static token creations.
     */
    protected static $tokenizer = null;

    /**
     * Tokenizer constructor.
     *
     * @param int $length The length of the token to generate.
     * @param string $alphabet The alphabet to be used by the Tokenizer.
     * @since 0.1
     */
    public function __construct(int $length = self::DEFAULT_LENGTH, string $alphabet = self::DEFAULT_ALPHABET)
    {
        $this->setLength($length);
        $this->setAlphabet($alphabet);
    }

    /**
     * Gets the length set in the Tokenizer.
     *
     * @return int Returns the length of the tokens to be created.
     * @since 0.1
     */
    public function getLength() : int
    {
        return $this->length;
    }

    /**
     * Sets the length of the tokens to be generated.
     *
     * @param int $length The length to be used by the Tokenizer. (Minimum value = 1)
     * @return Tokenizer Returns this instance for fluent interface.
     * @since 0.1
     */
    public function setLength(int $length) : Tokenizer
    {
        $this->length = max(1, $length);

        return $this;
    }

    /**
     * Gets the alphabet loaded in the Tokenizer.
     *
     * @return string Returns the loaded alphabet.
     * @since 0.1
     */
    public function getAlphabet() : string
    {
        return $this->alphabet;
    }

    /**
     * Sets the alphabet to be used by the Tokenizer.
     *
     * @param string $alphabet The alphabet to be used by the tokenizer.
     * @return Tokenizer Returns this instance for fluent interface.
     * @since 0.1
     */
    public function setAlphabet(string $alphabet = null) : Tokenizer
    {
        $this->alphabet = $alphabet ?? self::DEFAULT_ALPHABET;

        return $this;
    }

    /**
     * Makes a token using the configured length and alphabet.
     * Important: The generated token will be more secure if the alphabet is long enough.
     *
     * @see http://php.net/manual/en/function.random-int.php Generates cryptographically secure pseudo-random integers
     * @return string Returns the generated token.
     * @since 0.1
     */
    public function make() : string
    {
        $chars = $this->alphabet;
        $chars_ubound = strlen($chars) - 1;

        $token = '';
        for ($i = 0; $i < $this->length; $i++) {
            $token .= $chars[random_int(0, $chars_ubound)];
        }

        return $token;
    }

    /**
     * Makes a hexadecimal token using the configured length.
     * Important: The alphabet is not used with this method. Output chars are [0-1][a-f].
     *            The length is the length of the resulting hex string (it is not the length in bytes, though it may match).
     *
     * @see http://php.net/manual/en/function.random-bytes.php Generates cryptographically secure pseudo-random bytes
     * @return string Returns the generated hex token in lowercase.
     * @since 0.1
     */
    public function makeHex() : string
    {
        $bytes = random_bytes((int)round($this->length / 2, 0, PHP_ROUND_HALF_UP));
        $token = StringEncoder::rawToHex($bytes);

        return substr($token, 0, $this->length);
    }

    /**
     * Gets the current tokenizer or creates a new static tokenizer if length an alphabet differ.
     *
     * @param int $length The length of the token to generate.
     * @param string $alphabet The alphabet to be used by the Tokenizer.
     * @return Tokenizer Returns the current static tokenizer or a new one.
     */
    protected static function getTokenizer(int $length, string $alphabet = self::DEFAULT_ALPHABET)
    {
        if (self::$tokenizer == null || self::$tokenizer->length != $length || self::$tokenizer->alphabet != $alphabet) {
            self::$tokenizer = new self($length, $alphabet);
        }

        return self::$tokenizer;
    }

    /**
     * Generates a new token with the given length an alphabet.
     *
     * @param int $length The length of the token to generate.
     * @param string $alphabet The alphabet to be used by the Tokenizer.
     * @return string
     */
    public static function generate(int $length = self::DEFAULT_LENGTH, string $alphabet = self::DEFAULT_ALPHABET)
    {
        $tokenizer = self::getTokenizer($length, $alphabet);

        return $tokenizer->make();
    }

    /**
     * Generates a new hex token with the given length an alphabet.
     * Important: The alphabet is not used with this method. Output chars are [0-1][a-f].
     *            The length is the length of the resulting hex string (it is not the length in bytes, though it may match).
     *
     * @param int $length The length of the token to generate.
     * @return string
     */
    public static function generateHex(int $length = self::DEFAULT_LENGTH)
    {
        $tokenizer = self::getTokenizer($length);

        return $tokenizer->makeHex();
    }
}