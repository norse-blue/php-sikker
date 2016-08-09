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

namespace NorseBlue\Sikker\Tests\Keys;

use Codeception\Specify;
use Codeception\Test\Unit;
use NorseBlue\Sikker\Asymmetric\SignatureAlgorithm;

class SignatureAlgorithmTest extends Unit
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
     * Tests the type names
     */
    public function testTypeNames()
    {
        $this->specify('Converts the key types to name correctly.', function () {
            $this->assertEquals('sha1', SignatureAlgorithm::toName(SignatureAlgorithm::SHA1));
            $this->assertEquals('md5', SignatureAlgorithm::toName(SignatureAlgorithm::MD5));
            $this->assertEquals('md4', SignatureAlgorithm::toName(SignatureAlgorithm::MD4));
            $this->assertEquals('md2', SignatureAlgorithm::toName(SignatureAlgorithm::MD2));
            $this->assertEquals('dss1', SignatureAlgorithm::toName(SignatureAlgorithm::DSS1));
            $this->assertEquals('sha224', SignatureAlgorithm::toName(SignatureAlgorithm::SHA224));
            $this->assertEquals('sha256', SignatureAlgorithm::toName(SignatureAlgorithm::SHA256));
            $this->assertEquals('sha384', SignatureAlgorithm::toName(SignatureAlgorithm::SHA384));
            $this->assertEquals('sha512', SignatureAlgorithm::toName(SignatureAlgorithm::SHA512));
            $this->assertEquals('rmd160', SignatureAlgorithm::toName(SignatureAlgorithm::RMD160));
            $this->assertEquals('unknown', SignatureAlgorithm::toName(SignatureAlgorithm::UNKNOWN));
            $this->assertEquals('unknown', SignatureAlgorithm::toName(998));
        });

        $this->specify('Converts the key types from name correctly.', function () {
            $this->assertEquals(SignatureAlgorithm::SHA1, SignatureAlgorithm::fromName('sha1'));
            $this->assertEquals(SignatureAlgorithm::MD5, SignatureAlgorithm::fromName('md5'));
            $this->assertEquals(SignatureAlgorithm::MD4, SignatureAlgorithm::fromName('md4'));
            $this->assertEquals(SignatureAlgorithm::MD2, SignatureAlgorithm::fromName('md2'));
            $this->assertEquals(SignatureAlgorithm::DSS1, SignatureAlgorithm::fromName('dss1'));
            $this->assertEquals(SignatureAlgorithm::SHA224, SignatureAlgorithm::fromName('sha224'));
            $this->assertEquals(SignatureAlgorithm::SHA256, SignatureAlgorithm::fromName('sha256'));
            $this->assertEquals(SignatureAlgorithm::SHA384, SignatureAlgorithm::fromName('sha384'));
            $this->assertEquals(SignatureAlgorithm::SHA512, SignatureAlgorithm::fromName('sha512'));
            $this->assertEquals(SignatureAlgorithm::RMD160, SignatureAlgorithm::fromName('rmd160'));
            $this->assertEquals(SignatureAlgorithm::UNKNOWN, SignatureAlgorithm::fromName('unknown'));
            $this->assertEquals(SignatureAlgorithm::UNKNOWN, SignatureAlgorithm::fromName('not existent key'));
        });
    }
}
