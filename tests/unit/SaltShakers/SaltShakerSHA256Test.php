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

namespace NorseBlue\Sikker\Tests\SaltShakers;

use Codeception\Specify;
use Codeception\Test\Unit;
use Codeception\Util\Debug;
use NorseBlue\Sikker\SaltShakers\SaltShakerSHA256;

class SaltShakerSHA256Test extends Unit
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
            $saltShaker = new SaltShakerSHA256();
            $this->assertEquals(SaltShakerSHA256::DEFAULT_ROUNDS, $saltShaker->getRounds());
            $saltShaker->setRounds(3000);
            $this->assertEquals(3000, $saltShaker->getRounds());
            $saltShaker->setRounds(SaltShakerSHA256::MIN_ROUNDS - 100);    // Less than minimum
            $this->assertEquals(SaltShakerSHA256::MIN_ROUNDS, $saltShaker->getRounds());
            $saltShaker->setRounds(SaltShakerSHA256::MAX_ROUNDS + 100);    // More than maximum
            $this->assertEquals(SaltShakerSHA256::MAX_ROUNDS, $saltShaker->getRounds());
        });
    }

    /**
     * Tests encode method.
     */
    public function testEncode()
    {
        $this->specify('Encodes the given salt with maximum length.', function () {
            $salt = 'usesomesillystri';
            $saltShaker = new SaltShakerSHA256();
            $this->assertEquals('$5$rounds=5000$usesomesillystri$', $saltShaker->encode($salt));
        });

        $this->specify('Encodes the given salt longer than maximum length.', function () {
            $salt = 'usesomesillystringforsalt';
            $saltShaker = new SaltShakerSHA256();
            $this->assertEquals('$5$rounds=5000$usesomesillystri$', $saltShaker->encode($salt));
        });

        $this->specify('Encodes the given salt shorter than maximum length.', function () {
            $salt = 'usesomesilly';
            $saltShaker = new SaltShakerSHA256();
            $this->assertEquals('$5$rounds=5000$usesomesilly$', $saltShaker->encode($salt));
        });

        $this->specify('Encodes the given salt with a dollar sign.', function () {
            $salt = 'usesome$illystri';
            $saltShaker = new SaltShakerSHA256();
            $this->assertEquals('$5$rounds=5000$usesome$', $saltShaker->encode($salt));
        });

        $this->specify('Encodes the given empty salt.', function () {
            $salt = '';
            $saltShaker = new SaltShakerSHA256();
            $this->assertEquals('$5$rounds=5000$$', $saltShaker->encode($salt));
        });

        $this->specify('Encodes a random generated salt.', function () {
            $saltShaker = new SaltShakerSHA256();
            $encodedSalt = $saltShaker->encode();
            Debug::debug(sprintf("Random SHA256 encoded salt generated: %s\r\n", $encodedSalt));
            $this->assertEquals(32, strlen($encodedSalt));
        });
    }

    /**
     * Tests isValid function.
     */
    public function testIsValid()
    {
        $this->specify('Validates the correct given salt.', function () {
            $salt = '$5$rounds=5000$usesomesillystri$';
            $this->assertTrue(SaltShakerSHA256::isValid($salt));
        });

        $this->specify('Detects the incorrect given salt.', function () {
            $salt = '$5$rounds=5000$usesomesillystringforsalt$';    // Longer than what is expected
            $this->assertFalse(SaltShakerSHA256::isValid($salt));
        });

        $this->specify('Detects the incorrect rounds out of range (lower) given salt.', function () {
            $salt = '$5$rounds=999$usesomesillystri$';    // Rounds out of range
            $this->assertFalse(SaltShakerSHA256::isValid($salt));
        });

        $this->specify('Detects the incorrect rounds out of range (higher) given salt.', function () {
            $salt = '$5$rounds=1000000000$usesomesillystri$';    // Rounds out of range
            $this->assertFalse(SaltShakerSHA256::isValid($salt));
        });
    }
}