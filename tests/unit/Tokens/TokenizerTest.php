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

namespace NorseBlue\Sikker\Tests\Tokens;

use Codeception\Specify;
use Codeception\Test\Unit;
use Codeception\Util\Debug;
use NorseBlue\Sikker\Tokens\Tokenizer;

class TokenizerTest extends Unit
{
    use Specify;

    protected function _after()
    {
    }

    protected function _before()
    {
    }

    // tests

    /**
     * Tests getter and setter of the length property.
     */
    public function testGetSetLength()
    {
        $this->specify('Sets and gets the length correctly.', function () {
            $length = 32;
            $tokenizer = new Tokenizer();
            $this->assertEquals(Tokenizer::DEFAULT_LENGTH, $tokenizer->getLength());
            $tokenizer->setLength($length);
            $this->assertEquals($length, $tokenizer->getLength());
        });
    }

    /**
     * Tests getter and setter of the alphabet property.
     */
    public function testGetSetAlphabet()
    {
        $this->specify('Sets and gets the alphabet correctly.', function () {
            $alphabet = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789';
            $tokengen = new Tokenizer();
            $this->assertEquals(Tokenizer::DEFAULT_ALPHABET, $tokengen->getAlphabet());
            $tokengen->setAlphabet($alphabet);
            $this->assertEquals($alphabet, $tokengen->getAlphabet());
        });
    }

    /**
     * Tests the forge token method.
     */
    public function testMake()
    {
        $this->specify('Makes a random token using the given alphabet and length.', function () {
            $tokenizer = new Tokenizer();
            $token = $tokenizer->make();
            Debug::debug(sprintf("Made random token with length %d from alphabet '%s':\r\n%s\r\n",
                $tokenizer->getLength(), $tokenizer->getAlphabet(), $token));
            $this->assertEquals(Tokenizer::DEFAULT_LENGTH, strlen($token));
            $this->assertEquals(0, preg_match('/[^'.preg_quote(Tokenizer::DEFAULT_ALPHABET).']/', $token));
        });

        $this->specify('Makes a random token using the given reduced alphabet and length.', function () {
            $tokenLen = 8;
            $reducedAlphabet = 'ABCabc012';
            $tokenizer = new Tokenizer($tokenLen, $reducedAlphabet);
            $token = $tokenizer->make();
            Debug::debug(sprintf("Made random token with length %d from alphabet '%s':\r\n%s\r\n",
                $tokenizer->getLength(), $tokenizer->getAlphabet(), $token));
            $this->assertEquals($tokenLen, strlen($token));
            $this->assertEquals(0, preg_match('/[^'.preg_quote($reducedAlphabet).']/', $token));
        });
    }

    /**
     * Tests the forge hex method.
     */
    public function testMakeHex()
    {
        $this->specify('Makes a random hex token using the given length.', function () {
            $tokenizer = new Tokenizer();
            $token = $tokenizer->makeHex();
            Debug::debug(sprintf("Made random hex token with length %d:\r\n%s\r\n",
                $tokenizer->getLength(), $token));
            $this->assertEquals(Tokenizer::DEFAULT_LENGTH, strlen($token));
            $this->assertEquals(0, preg_match('/[^'.preg_quote('0123456789abcdef').']/', $token));
        });

        $this->specify('Makes a random hex token using the given length.', function () {
            $tokenLen = 3;
            $tokenizer = new Tokenizer($tokenLen);
            $token = $tokenizer->makeHex();
            Debug::debug(sprintf("Made random hex token with length %d:\r\n%s\r\n",
                $tokenizer->getLength(), $token));
            $this->assertEquals($tokenLen, strlen($token));
            $this->assertEquals(0, preg_match('/[^'.preg_quote('0123456789abcdef').']/', $token));
        });
    }

    public function testGenerate()
    {
        $this->specify('Generates a random token using the given alphabet and length.', function () {
            $token = Tokenizer::generate();
            Debug::debug(sprintf("Generated random token with length %d from alphabet '%s':\r\n%s\r\n",
                Tokenizer::DEFAULT_LENGTH, Tokenizer::DEFAULT_ALPHABET, $token));
            $this->assertEquals(Tokenizer::DEFAULT_LENGTH, strlen($token));
            $this->assertEquals(0, preg_match('/[^'.preg_quote(Tokenizer::DEFAULT_ALPHABET).']/', $token));
        });

        $this->specify('Generates a random token using the given reduced alphabet and length.', function () {
            $tokenLen = 8;
            $reducedAlphabet = 'ABCabc012';
            $token = Tokenizer::generate($tokenLen, $reducedAlphabet);
            Debug::debug(sprintf("Generated random token with length %d from alphabet '%s':\r\n%s\r\n",
                $tokenLen, $reducedAlphabet, $token));
            $this->assertEquals($tokenLen, strlen($token));
            $this->assertEquals(0, preg_match('/[^'.preg_quote($reducedAlphabet).']/', $token));
        });
    }

    public function testGenerateHex()
    {
        $this->specify('Generates a random hex token using the given length.', function () {
            $token = Tokenizer::generateHex();
            Debug::debug(sprintf("Generated random hex token with length %d:\r\n%s\r\n",
                Tokenizer::DEFAULT_LENGTH, $token));
            $this->assertEquals(Tokenizer::DEFAULT_LENGTH, strlen($token));
            $this->assertEquals(0, preg_match('/[^'.preg_quote('0123456789abcdef').']/', $token));
        });

        $this->specify('Generates a random hex token using the given length.', function () {
            $tokenLen = 3;
            $token = Tokenizer::generateHex($tokenLen);
            Debug::debug(sprintf("Generated random hex token with length %d:\r\n%s\r\n",
                $tokenLen, $token));
            $this->assertEquals($tokenLen, strlen($token));
            $this->assertEquals(0, preg_match('/[^'.preg_quote('0123456789abcdef').']/', $token));
        });
    }
}