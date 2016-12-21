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

namespace NorseBlue\Sikker\Tests\Passwords;

use Codeception\Specify;
use Codeception\Test\Unit;
use Mockery;
use NorseBlue\Sikker\Passwords\Password;
use NorseBlue\Sikker\SaltShakers\SaltShaker;
use NorseBlue\Sikker\SaltShakers\SaltShakerBlowfish;
use NorseBlue\Sikker\SaltShakers\SaltShakerExtDES;
use NorseBlue\Sikker\SaltShakers\SaltShakerMD5;
use NorseBlue\Sikker\SaltShakers\SaltShakerSHA256;
use NorseBlue\Sikker\SaltShakers\SaltShakerSHA512;
use NorseBlue\Sikker\SaltShakers\SaltShakerStdDES;

class PasswordTest extends Unit
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
     * Tests getter and setter of the plain password property.
     */
    public function testGetSetPlainPassword()
    {
        $this->specify('Sets and gets the plain password correctly.', function () {
            $plain = 'Winter1sComing!';
            $plain2 = 'YouKnowN0thing';
            $pwd = new Password($plain);
            $this->assertEquals($plain, $pwd->getPlain());
            $pwd->setPlain($plain2);
            $this->assertNotEquals($plain, $pwd->getPlain());
            $this->assertEquals($plain2, $pwd->getPlain());
        });
    }

    /**
     * Tests getter of the hashed password.
     */
    public function testGetHashedPassword()
    {
        $this->specify('Gets the hashed password correctly.', function () {
            $plain = 'rasmuslerdorf';
            $saltShaker = Mockery::mock(SaltShakerSHA256::class, function ($mock) {
                $mock->shouldReceive('encode')->with('usesomesillystringforsalt')->andReturn('$5$rounds=5000$usesomesillystringforsalt$');
            });
            $pwd = new Password($plain, $saltShaker);
            $this->assertEquals('$5$rounds=5000$usesomesillystri$KqJWpanXZHKq2BOB43TSaYhEWsQ1Lr5QNyPCDH/Tp.6',
                $pwd->getHashed('usesomesillystringforsalt'));
        });
    }

    /**
     * Tests getter and setter of the saltShaker property.
     */
    public function testGetSetSaltShaker()
    {
        $this->specify('Sets and gets the saltShaker correctly.', function () {
            $saltShaker = Mockery::mock(SaltShaker::class);
            $saltShakerNew = Mockery::mock(SaltShaker::class);
            $pwd = new Password(null, $saltShaker);
            $this->assertSame($saltShaker, $pwd->getSaltShaker());
            $pwd->setSaltShaker($saltShakerNew);
            $this->assertNotSame($saltShaker, $pwd->getSaltShaker());
            $this->assertSame($saltShakerNew, $pwd->getSaltShaker());
        });
    }

    /**
     * Tests the hash password method.
     * Examples taken from {@link http://php.net/manual/en/function.crypt.php PHP crypt function reference.}
     */
    public function testHash()
    {
        $this->specify('Tests the password hash using BLOWFISH.', function () {
            $saltShaker = Mockery::mock(SaltShakerBlowfish::class, function ($mock) {
                $mock->shouldReceive('encode')->with('usesomesillystringforsalt')->andReturn('$2a$07$usesomesillystringforsalt$');
            });
            $pwd = new Password(null, $saltShaker);
            $this->assertEquals('$2a$07$usesomesillystringfore2uDLvp1Ii2e./U9C8sBjqp8I90dH6hi',
                $pwd->hash('rasmuslerdorf', 'usesomesillystringforsalt'));
        });

        $this->specify('Tests the password hash using ExtDES.', function () {
            $saltShaker = Mockery::mock(SaltShakerExtDES::class, function ($mock) {
                $mock->shouldReceive('encode')->with('rasm')->andReturn('_J9..rasm');
            });
            $pwd = new Password(null, $saltShaker);
            $this->assertEquals('_J9..rasmBYk8r9AiWNc', $pwd->hash('rasmuslerdorf', 'rasm'));
        });

        $this->specify('Tests the password hash using MD5.', function () {
            $saltShaker = Mockery::mock(SaltShakerMD5::class, function ($mock) {
                $mock->shouldReceive('encode')->with('rasmusle')->andReturn('$1$rasmusle$');
            });
            $pwd = new Password(null, $saltShaker);
            $this->assertEquals('$1$rasmusle$rISCgZzpwk3UhDidwXvin0', $pwd->hash('rasmuslerdorf', 'rasmusle'));
        });

        $this->specify('Tests the password hash using SHA256.', function () {
            $saltShaker = Mockery::mock(SaltShakerSHA256::class, function ($mock) {
                $mock->shouldReceive('encode')->with('usesomesillystringforsalt')->andReturn('$5$rounds=5000$usesomesillystringforsalt$');
            });
            $pwd = new Password(null, $saltShaker);
            $this->assertEquals('$5$rounds=5000$usesomesillystri$KqJWpanXZHKq2BOB43TSaYhEWsQ1Lr5QNyPCDH/Tp.6',
                $pwd->hash('rasmuslerdorf', 'usesomesillystringforsalt'));
        });

        $this->specify('Tests the password hash using SHA512.', function () {
            $saltShaker = Mockery::mock(SaltShakerSHA512::class, function ($mock) {
                $mock->shouldReceive('encode')->with('usesomesillystringforsalt')->andReturn('$6$rounds=5000$usesomesillystringforsalt$');
            });
            $pwd = new Password(null, $saltShaker);
            $this->assertEquals('$6$rounds=5000$usesomesillystri$D4IrlXatmP7rx3P3InaxBeoomnAihCKRVQP22JZ6EY47Wc6BkroIuUUBOov1i.S5KPgErtP/EN5mcO.ChWQW21',
                $pwd->hash('rasmuslerdorf', 'usesomesillystringforsalt'));
        });

        $this->specify('Tests the password hash using StdDES.', function () {
            $saltShaker = Mockery::mock(SaltShakerStdDES::class, function ($mock) {
                $mock->shouldReceive('encode')->with('rl')->andReturn('rl');
            });
            $pwd = new Password(null, $saltShaker);
            $this->assertEquals('rl.3StKT.4T8M', $pwd->hash('rasmuslerdorf', 'rl'));
        });
    }

    /**
     * Tests the verify password method.
     * Examples taken from {@link http://php.net/manual/en/function.crypt.php PHP crypt function reference.}
     */
    public function testVerify()
    {
        $this->specify('Test the password against the BLOWFISH hash.', function () {
            $this->assertTrue(Password::verify('rasmuslerdorf',
                '$2a$07$usesomesillystringfore2uDLvp1Ii2e./U9C8sBjqp8I90dH6hi'));
            $this->assertFalse(Password::verify('rasmuslerdorf', 'incorrecthash'));
        });

        $this->specify('Test the password against the ExtDES hash.', function () {
            $this->assertTrue(Password::verify('rasmuslerdorf', '_J9..rasmBYk8r9AiWNc'));
            $this->assertFalse(Password::verify('rasmuslerdorf', 'incorrecthash'));

        });

        $this->specify('Test the password against the MD5 hash.', function () {
            $this->assertTrue(Password::verify('rasmuslerdorf', '$1$rasmusle$rISCgZzpwk3UhDidwXvin0'));
            $this->assertFalse(Password::verify('rasmuslerdorf', 'incorrecthash'));

        });

        $this->specify('Test the password against the SHA256 hash.', function () {
            $this->assertTrue(Password::verify('rasmuslerdorf',
                '$5$rounds=5000$usesomesillystri$KqJWpanXZHKq2BOB43TSaYhEWsQ1Lr5QNyPCDH/Tp.6'));
            $this->assertFalse(Password::verify('rasmuslerdorf', 'incorrecthash'));

        });

        $this->specify('Test the password against the SHA512 hash.', function () {
            $this->assertTrue(Password::verify('rasmuslerdorf',
                '$6$rounds=5000$usesomesillystri$D4IrlXatmP7rx3P3InaxBeoomnAihCKRVQP22JZ6EY47Wc6BkroIuUUBOov1i.S5KPgErtP/EN5mcO.ChWQW21'));
            $this->assertFalse(Password::verify('rasmuslerdorf', 'incorrecthash'));

        });

        $this->specify('Test the password against the StdDES hash.', function () {
            $this->assertTrue(Password::verify('rasmuslerdorf', 'rl.3StKT.4T8M'));
            $this->assertFalse(Password::verify('rasmuslerdorf', 'incorrecthash'));

        });
    }
}