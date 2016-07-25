<?php
/**
 * Sikker is a PHP 7.0+ Security package that contains security related implementations.
 *
 * @package    NorseBlue\Sikker
 * @version    0.1.1
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
use NorseBlue\Sikker\Passwords\SaltShakers\SaltShakerMD5;

class SaltShakerMD5Test extends Unit
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
     * Tests encode method.
     */
    public function testEncode()
    {
        $this->specify('Encodes the given salt with maximum length.', function () {
            $salt = 'rasmusle';
            $saltShaker = new SaltShakerMD5();
            $this->assertEquals('$1$rasmusle$', $saltShaker->encode($salt));
        });

        $this->specify('Encodes the given salt longer than maximum length.', function () {
            $salt = 'rasmuslerdorf';
            $saltShaker = new SaltShakerMD5();
            $this->assertEquals('$1$rasmusle$', $saltShaker->encode($salt));
        });

        $this->specify('Encodes the given salt shorter than maximum length.', function () {
            $salt = 'rasmus';
            $saltShaker = new SaltShakerMD5();
            $this->assertEquals('$1$rasmus$', $saltShaker->encode($salt));
        });

        $this->specify('Encodes the given salt with a dollar sign.', function () {
            $salt = 'ras$mus';
            $saltShaker = new SaltShakerMD5();
            $this->assertEquals('$1$ras$', $saltShaker->encode($salt));
        });

        $this->specify('Encodes the given empty salt.', function () {
            $salt = '';
            $saltShaker = new SaltShakerMD5();
            $this->assertEquals('$1$$', $saltShaker->encode($salt));
        });

        $this->specify('Encodes a random generated salt.', function () {
            $saltShaker = new SaltShakerMD5();
            $encodedSalt = $saltShaker->encode();
            Debug::debug(sprintf("Random MD5 encoded salt generated: %s\r\n", $encodedSalt));
            $this->assertEquals(12, strlen($encodedSalt));
        });
    }

    /**
     * Tests isValid function.
     */
    public function testIsValid()
    {
        $this->specify('Validates the correct given salt.', function () {
            $salt = '$1$rasmusle$';
            $this->assertTrue(SaltShakerMD5::isValid($salt));
        });

        $this->specify('Detects the incorrect given salt.', function () {
            $salt = '$1$rasmuslerdorf$';    // Longer than what is expected
            $this->assertFalse(SaltShakerMD5::isValid($salt));
        });
    }
}