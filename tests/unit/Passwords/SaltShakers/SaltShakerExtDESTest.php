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
use NorseBlue\Sikker\Passwords\SaltShakers\SaltShakerExtDES;

class SaltShakerExtDESTest extends Unit
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
     * Tests the getter and setter of the property rounds.
     */
    public function testGetSetRounds()
    {
        $this->specify('Gets and sets the rounds property.', function () {
            $saltShaker = new SaltShakerExtDES();
            $this->assertEquals(SaltShakerExtDES::DEFAULT_ROUNDS, $saltShaker->getRounds());
            $saltShaker->setRounds(3000);
            $this->assertEquals(3000, $saltShaker->getRounds());
            $saltShaker->setRounds(SaltShakerExtDES::MIN_ROUNDS - 100);    // Less than minimum
            $this->assertEquals(SaltShakerExtDES::MIN_ROUNDS, $saltShaker->getRounds());
            $saltShaker->setRounds(SaltShakerExtDES::MAX_ROUNDS + 100);    // More than maximum
            $this->assertEquals(SaltShakerExtDES::MAX_ROUNDS, $saltShaker->getRounds());
        });
    }

    /**
     * Tests encode function.
     */
    public function testEncode()
    {
        $this->specify('Encodes the given salt with maximum length.', function () {
            $salt = 'rasm';
            $saltShaker = new SaltShakerExtDES();
            $this->assertEquals('_J9..rasm', $saltShaker->encode($salt));
        });

        $this->specify('Encodes the given salt longer than maximum length.', function () {
            $salt = 'rlerdorf';
            $saltShaker = new SaltShakerExtDES();
            $this->assertEquals('_J9..rler', $saltShaker->encode($salt));
        });

        $this->specify('Encodes the given salt shorter than maximum length.', function () {
            $salt = 'rl';
            $saltShaker = new SaltShakerExtDES();
            $encodedSalt = $saltShaker->encode($salt);
            Debug::debug(sprintf("Random ExtDES encoded shorter salt with completion: %s\r\n", $encodedSalt));
            $this->assertEquals(9, strlen($encodedSalt));
            $this->assertEquals('_J9..rl', substr($encodedSalt, 0, 7));
        });

        $this->specify('Encodes the given empty salt.', function () {
            $salt = '';
            $saltShaker = new SaltShakerExtDES();
            $encodedSalt = $saltShaker->encode($salt);
            Debug::debug(sprintf("Random ExtDES encoded empty salt with completion: %s\r\n", $encodedSalt));
            $this->assertEquals(9, strlen($encodedSalt));
        });

        $this->specify('Encodes a random generated salt.', function () {
            $saltShaker = new SaltShakerExtDES();
            $encodedSalt = $saltShaker->encode();
            Debug::debug(sprintf("Random ExtDES encoded salt generated: %s\r\n", $encodedSalt));
            $this->assertEquals(9, strlen($encodedSalt));
        });

        $this->specify('Encodes the given salt with a character that is not part of the alphabet.', function () {
            $salt = 'r$';
            $saltShaker = new SaltShakerExtDES();
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
            $salt = '_J9..rasm';
            $this->assertTrue(SaltShakerExtDES::isValid($salt));
        });

        $this->specify('Detects the incorrect shorter given salt.', function () {
            $salt = '_J9..';    // Shorter than what is expected
            $this->assertFalse(SaltShakerExtDES::isValid($salt));
        });

        $this->specify('Detects the incorrect longer given salt.', function () {
            $salt = '_J9..rasmuslerdorf';    // Longer than what is expected
            $this->assertFalse(SaltShakerExtDES::isValid($salt));
        });
    }
}