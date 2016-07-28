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

namespace NorseBlue\Sikker\Tests\SaltShakers;

use Codeception\Specify;
use Codeception\Test\Unit;
use Codeception\Util\Debug;
use InvalidArgumentException;
use NorseBlue\Sikker\SaltShakers\SaltShakerBlowfish;

class SaltShakerBlowfishTest extends Unit
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
     * Tests the getter and setter of the property mode.
     */
    public function testGetSetMode()
    {
        $this->specify('Gets and sets the mode property.', function () {
            $saltShaker = new SaltShakerBlowfish();
            $this->assertEquals(SaltShakerBlowfish::DEFAULT_MODE, $saltShaker->getMode());
            $saltShaker->setMode(SaltShakerBlowfish::MODE_X);
            $this->assertEquals(SaltShakerBlowfish::MODE_X, $saltShaker->getMode());
            $saltShaker->setMode(SaltShakerBlowfish::MODE_A);
            $this->assertEquals(SaltShakerBlowfish::MODE_A, $saltShaker->getMode());
            $saltShaker->setMode('NonExistentMode');
            $this->assertEquals(SaltShakerBlowfish::DEFAULT_MODE, $saltShaker->getMode());
        });
    }

    /**
     * Tests the getter and setter of the property cost.
     */
    public function testGetSetCost()
    {
        $this->specify('Gets and sets the cost property.', function () {
            $saltShaker = new SaltShakerBlowfish();
            $this->assertEquals(SaltShakerBlowfish::DEFAULT_COST, $saltShaker->getCost());
            $saltShaker->setCost(7);
            $this->assertEquals(7, $saltShaker->getCost());
            $saltShaker->setCost(SaltShakerBlowfish::MIN_COST - 2);    // Less than minimum
            $this->assertEquals(SaltShakerBlowfish::MIN_COST, $saltShaker->getCost());
            $saltShaker->setCost(SaltShakerBlowfish::MAX_COST + 2);    // More than maximum
            $this->assertEquals(SaltShakerBlowfish::MAX_COST, $saltShaker->getCost());
        });
    }

    /**
     * Tests encode function.
     */
    public function testEncode()
    {
        $this->specify('Encodes the given salt with maximum length.', function () {
            $salt = 'usesomesillystringfors';
            $saltShaker = new SaltShakerBlowfish();
            $this->assertEquals('$2y$10$usesomesillystringfor$', $saltShaker->encode($salt));
        });

        $this->specify('Encodes the given salt longer than maximum length.', function () {
            $salt = 'usesomesillystringforsalt';
            $saltShaker = new SaltShakerBlowfish();
            $this->assertEquals('$2y$10$usesomesillystringfor$', $saltShaker->encode($salt));
        });

        $this->specify('Encodes the given salt shorter than maximum length.', function () {
            $salt = 'usesomesilly';
            $saltShaker = new SaltShakerBlowfish();
            $encodedSalt = $saltShaker->encode($salt);
            Debug::debug(sprintf("Random Blowfish encoded shorter salt with completion: %s\r\n", $encodedSalt));
            $this->assertEquals(29, strlen($encodedSalt));
            $this->assertEquals('$2y$10$usesomesilly', substr($encodedSalt, 0, 19));
        });

        $this->specify('Encodes the given empty salt.', function () {
            $salt = '';
            $saltShaker = new SaltShakerBlowfish();
            $encodedSalt = $saltShaker->encode($salt);
            Debug::debug(sprintf("Random Blowfish encoded empty salt with completion: %s\r\n", $encodedSalt));
            $this->assertEquals(29, strlen($encodedSalt));
            $this->assertEquals('$2y$10$', substr($encodedSalt, 0, 7));
        });

        $this->specify('Encodes a random generated salt.', function () {
            $saltShaker = new SaltShakerBlowfish();
            $encodedSalt = $saltShaker->encode();
            Debug::debug(sprintf("Random Blowfish encoded salt generated: %s\r\n", $encodedSalt));
            $this->assertEquals(29, strlen($encodedSalt));
            $this->assertEquals('$2y$10$', substr($encodedSalt, 0, 7));
        });

        $this->specify('Encodes the given salt with a character that is not part of the alphabet.', function () {
            $salt = 'usesome$illystri';
            $saltShaker = new SaltShakerBlowfish();
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
            $salt = '$2a$07$usesomesillystringfor$';
            $this->assertTrue(SaltShakerBlowfish::isValid($salt));
        });

        $this->specify('Detects the incorrect shorter given salt.', function () {
            $salt = '$2a$07$usesomesilly$';    // Shorter than what is expected
            $this->assertFalse(SaltShakerBlowfish::isValid($salt));
        });

        $this->specify('Detects the incorrect longer given salt.', function () {
            $salt = '$2a$07$usesomesillystringforsalt$';    // Longer than what is expected
            $this->assertFalse(SaltShakerBlowfish::isValid($salt));
        });

        $this->specify('Detects the incorrect cost out of range (lower) given salt.', function () {
            $salt = '$2a$03$usesomesillystringfor$';    // Cost out of range
            $this->assertFalse(SaltShakerBlowfish::isValid($salt));
        });

        $this->specify('Detects the incorrect cost out of range (higher) given salt.', function () {
            $salt = '$2a$32$usesomesillystringfor$';    // Cost out of range
            $this->assertFalse(SaltShakerBlowfish::isValid($salt));
        });
    }
}