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

namespace NorseBlue\Sikker\Tests\Passwords\SaltShakers;

use Codeception\Specify;
use Codeception\Test\Unit;
use Codeception\Util\Debug;
use InvalidArgumentException;
use NorseBlue\Sikker\Passwords\SaltShakers\SaltShakerStdDES;

class SaltShakerStdDESTest extends Unit
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
     * Tests encode function.
     */
    public function testEncode()
    {
        $this->specify('Encodes the given salt with maximum length.', function () {
            $salt = 'rl';
            $saltShaker = new SaltShakerStdDES();
            $this->assertEquals('rl', $saltShaker->encode($salt));
        });

        $this->specify('Encodes the given salt longer than maximum length.', function () {
            $salt = 'rlerdorf';
            $saltShaker = new SaltShakerStdDES();
            $this->assertEquals('rl', $saltShaker->encode($salt));
        });

        $this->specify('Encodes the given salt shorter than maximum length.', function () {
            $salt = 'r';
            $saltShaker = new SaltShakerStdDES();
            $encodedSalt = $saltShaker->encode($salt);
            Debug::debug(sprintf("Random StdDES encoded shorter salt with completion: %s\r\n", $encodedSalt));
            $this->assertEquals(2, strlen($encodedSalt));
            $this->assertEquals('r', substr($encodedSalt, 0, 1));
        });

        $this->specify('Encodes the given empty salt.', function () {
            $salt = '';
            $saltShaker = new SaltShakerStdDES();
            $encodedSalt = $saltShaker->encode($salt);
            Debug::debug(sprintf("Random StdDES encoded empty salt with completion: %s\r\n", $encodedSalt));
            $this->assertEquals(2, strlen($encodedSalt));
        });

        $this->specify('Encodes a random generated salt.', function () {
            $saltShaker = new SaltShakerStdDES();
            $encodedSalt = $saltShaker->encode();
            Debug::debug(sprintf("Random StdDES encoded salt generated: %s\r\n", $encodedSalt));
            $this->assertEquals(2, strlen($encodedSalt));
        });

        $this->specify('Encodes the given salt with a character that is not part of the alphabet.', function () {
            $salt = 'r$';
            $saltShaker = new SaltShakerStdDES();
            $this->expectException(InvalidArgumentException::class);
            $encodedSalt = $saltShaker->encode($salt);
        });
    }

    /**
     * Tests isValid function.
     */
    public function testIsValid()
    {
        $this->specify('Validates the correct given salt.', function () {
            $salt = 'rl';
            $this->assertTrue(SaltShakerStdDES::isValid($salt));
        });

        $this->specify('Detects the incorrect shorter given salt.', function () {
            $salt = 'r';    // Shorter than what is expected
            $this->assertFalse(SaltShakerStdDES::isValid($salt));
        });

        $this->specify('Detects the incorrect longer given salt.', function () {
            $salt = 'rasmuslerdorf';    // Longer than what is expected
            $this->assertFalse(SaltShakerStdDES::isValid($salt));
        });
    }
}