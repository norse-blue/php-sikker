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

namespace NorseBlue\Sikker\Tokens;

/**
 * Class Tokenizer
 *
 * @package NorseBlue\Sikker\Tokens
 * @since 0.1
 */
class TokenFactory
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
     * @return TokenFactory Returns this instance for fluent interface.
     * @since 0.1
     */
    public function setLength(int $length) : TokenFactory
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
     * @return TokenFactory Returns this instance for fluent interface.
     * @since 0.1
     */
    public function setAlphabet(string $alphabet = null) : TokenFactory
    {
        $this->alphabet = $alphabet ?? self::DEFAULT_ALPHABET;
        return $this;
    }

    /**
     * Generates a token using the configured length and alphabet.
     * Important: The generated token will be more secure if the alphabet is long enough.
     *
     * @return string Returns the generated token.
     * @since 0.1
     */
    public function forgeToken() : string
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
     * Generates a hexadecimal token using the configured length.
     * Important: The alphabet is not used with this method. Output chars are [0-1][a-f].
     *            The length is the length of the resulting string (it is not the length in bytes).
     *
     * @return string Returns the generated hex token in lowercase.
     * @since 0.1
     */
    public function forgeHexToken() : string
    {
        $bytes = random_bytes((int) round($this->length / 2, 0, PHP_ROUND_HALF_UP));
        $token = bin2hex($bytes);

        return substr($token, 0, $this->length);
    }
}