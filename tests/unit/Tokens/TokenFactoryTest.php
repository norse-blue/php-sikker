<?php
/**
 * Sikker is a PHP 7.0+ Security package that contains security related implementations.
 *
 * @package    NorseBlue\Sikker
 * @version    0.1
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
use NorseBlue\Sikker\Tokens\TokenFactory;

class TokenFactoryTest extends Unit
{
    use Specify;

    protected function _after()
    {
    }

    protected function _before()
    {
    }

    // tests

    public function testGetSetLength()
    {
        $this->specify('Sets and gets the length correctly.', function () {
            $length = 32;
            $tokenizer = new TokenFactory();
            $this->assertEquals(TokenFactory::DEFAULT_LENGTH, $tokenizer->getLength());
            $tokenizer->setLength($length);
            $this->assertEquals($length, $tokenizer->getLength());
        });
    }

    public function testGetSetAlphabet()
    {
        $this->specify('Sets and gets the alphabet correctly.', function () {
            $alphabet = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789';
            $tokengen = new TokenFactory();
            $this->assertEquals(TokenFactory::DEFAULT_ALPHABET, $tokengen->getAlphabet());
            $tokengen->setAlphabet($alphabet);
            $this->assertEquals($alphabet, $tokengen->getAlphabet());
        });
    }

    public function testForgeToken()
    {
        $this->specify('Generates a random token using the given alphabet and length.', function () {
            $tokenFactory = new TokenFactory();
            $token = $tokenFactory->forgeToken();
            Debug::debug(sprintf("Forged random token with length %d from alphabet '%s':\r\n%s\r\n",
                $tokenFactory->getLength(), $tokenFactory->getAlphabet(), $token));
            $this->assertEquals(TokenFactory::DEFAULT_LENGTH, strlen($token));
            $this->assertEquals(0, preg_match('/[^' . preg_quote(TokenFactory::DEFAULT_ALPHABET) . ']/', $token));
        });

        $this->specify('Generates a random token using the given reduced alphabet and length.', function () {
            $tokenLen = 8;
            $reducedAlphabet = 'ABCabc012';
            $tokenFactory = new TokenFactory($tokenLen, $reducedAlphabet);
            $token = $tokenFactory->forgeToken();
            Debug::debug(sprintf("Forged random token with length %d from alphabet '%s':\r\n%s\r\n",
                $tokenFactory->getLength(), $tokenFactory->getAlphabet(), $token));
            $this->assertEquals($tokenLen, strlen($token));
            $this->assertEquals(0, preg_match('/[^' . preg_quote($reducedAlphabet) . ']/', $token));
        });
    }

    public function testCalculateRepeatabilityFactor()
    {
        $this->specify('', function () {
            $token = 'CnRwh61ygUUEAs8o2JphrOGrfZ8sxSLr';
            $repeatabilityFactor = 0.1875;      //  6(repeats) / 32(length)
            $this->assertEquals($repeatabilityFactor, TokenFactory::calculateRepeatabilityFactor($token));
        });
    }
}