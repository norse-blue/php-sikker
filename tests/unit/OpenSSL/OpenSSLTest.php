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

namespace NorseBlue\Sikker\Tests\OpenSSL;

use Codeception\Specify;
use Codeception\Test\Unit;
use NorseBlue\Sikker\OpenSSL\OpenSSL;
use NorseBlue\Sikker\OpenSSL\OpenSSLNotAvailableException;

class OpenSSLTest extends Unit
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
     * Tests the generate function.
     */
    public function testIsAvailable()
    {
        $this->specify('Tests if OpenSSL is available (loaded).', function () {
            if (extension_loaded('openssl')) {
                $this->assertTrue(OpenSSL::isAvailable());
            } else {
                $this->assertFalse(OpenSSL::isAvailable());
                $this->expectException(OpenSSLNotAvailableException::class);
                OpenSSL::isAvailable(true);
            }
        });
    }

    /**
     * Tests the getConfiguration function.
     */
    public function testGetConfiguration()
    {
        $this->specify('Tests the OpenSSL configuration retrieval function.', function () {
            if (extension_loaded('openssl')) {
                $config = OpenSSL::getConfiguration();
                if (getenv('OPENSSL_CONF') !== false || getenv('SSLEAY_CONF') !== false) {
                    $this->assertInternalType('string', $config);
                } else {
                    $this->assertFalse($config);
                }
            } else {
                $this->expectException(OpenSSLNotAvailableException::class);
                OpenSSL::getConfiguration();
            }
        });
    }

    /**
     * Tests the getErrors function.
     */
    public function testGetErrors()
    {
        $this->specify('Tests the OpenSSL get errors function.', function () {
            if (extension_loaded('openssl')) {
                $this->assertInternalType('array', OpenSSL::getErrors());
            } else {
                $this->expectException(OpenSSLNotAvailableException::class);
                OpenSSL::getErrors();
            }
        });
    }
}
