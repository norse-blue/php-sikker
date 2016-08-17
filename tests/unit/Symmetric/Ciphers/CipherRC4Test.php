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

namespace NorseBlue\Sikker\Tests\Symmetric\Ciphers;

use Codeception\Specify;
use Codeception\Test\Unit;
use InvalidArgumentException;
use NorseBlue\Sikker\Symmetric\CipherMethod;
use NorseBlue\Sikker\Symmetric\KeySize;
use NorseBlue\Sikker\Symmetric\Ciphers\CipherRC4;

class CipherRC4Test extends Unit
{
    use Specify;

    /**
     * @var string Helper payload to encrypt.
     */
    const PAYLOAD = 'You know nothing Jon Snow! Winter is coming!';

    /**
     * @var string Helper password to encrypt.
     */
    const PASSWORD = 'The White Wolf';

    /**
     * @var string The password as hex string.
     */
    const PASSWORD_HEX = '54686520576869746520576F6c66';

    /**
     * @var string The payload encrypted with RC4-128 and the password.
     */
    const ENCRYPTED_PAYLOAD_RC4128_BASE64 = 'A0GQypAVZkOfBoKWS0RfzS/STQwuoGzevVHOoYYNS7Xhr2WzbUKPQUvRkTM=';

    /**
     * @var string The payload encrypted with RC4-64 and the password.
     */
    const ENCRYPTED_PAYLOAD_RC464_BASE64 = '';

    /**
     * @var string The payload encrypted with RC4-40 and the password.
     */
    const ENCRYPTED_PAYLOAD_RC440_BASE64 = '7Z+8qDFP+Rq/2CjHKT8ZaQw/oM0my14NQ7EL3PSkO98Wc5+Erm6+TqvRhak=';

    protected function _after()
    {
    }

    protected function _before()
    {
    }

    // tests

    /**
     * Test incorrect key size
     */
    public function testIncorrectKeySize()
    {
        $this->specify('', function () {
            $this->expectException(InvalidArgumentException::class);
            $cipher = new CipherRC4(998);
        });
    }

    /**
     * Tests the type names
     */
    public function testEncryptionDecryption()
    {
        $this->specify('Encrypts and decrypts the payload with RC4-128', function () {
            if (extension_loaded('openssl') && CipherMethod::isAvailable(CipherMethod::RC4)) {
                $cipher = new CipherRC4(KeySize::_128);
                $encrypted = $cipher->encrypt(self::PAYLOAD, self::PASSWORD);
                $this->assertInternalType('array', $encrypted);
                $this->assertEquals(5, count($encrypted));
                $this->assertEquals(self::ENCRYPTED_PAYLOAD_RC4128_BASE64, $encrypted[0]);
                $this->assertEquals(strtolower(self::PASSWORD_HEX), strtolower($encrypted[1]));
                $this->assertEquals(0, $encrypted[2]);
                $this->assertEquals('', $encrypted[3]);

                $decrypted = $cipher->decrypt(self::ENCRYPTED_PAYLOAD_RC4128_BASE64, self::PASSWORD);
                $this->assertEquals(self::PAYLOAD, $decrypted);
            }
        });

        $this->specify('Encrypts and decrypts the payload with RC4-64', function () {
            if (extension_loaded('openssl') && CipherMethod::isAvailable(CipherMethod::RC4_64)) {
                $cipher = new CipherRC4(KeySize::_64);
                $encrypted = $cipher->encrypt(self::PAYLOAD, self::PASSWORD);
                $this->assertInternalType('array', $encrypted);
                $this->assertEquals(5, count($encrypted));
                $this->assertEquals(self::ENCRYPTED_PAYLOAD_RC464_BASE64, $encrypted[0]);
                $this->assertEquals(strtolower(self::PASSWORD_HEX), strtolower($encrypted[1]));
                $this->assertEquals(0, $encrypted[2]);
                $this->assertEquals('', $encrypted[3]);

                $decrypted = $cipher->decrypt(self::ENCRYPTED_PAYLOAD_RC464_BASE64, self::PASSWORD);
                $this->assertEquals(self::PAYLOAD, $decrypted);
            }
        });

        $this->specify('Encrypts and decrypts the payload with RC4-40', function () {
            if (extension_loaded('openssl') && CipherMethod::isAvailable(CipherMethod::RC4_40)) {
                $cipher = new CipherRC4(KeySize::_40);
                $encrypted = $cipher->encrypt(self::PAYLOAD, self::PASSWORD);
                $this->assertInternalType('array', $encrypted);
                $this->assertEquals(5, count($encrypted));
                $this->assertEquals(self::ENCRYPTED_PAYLOAD_RC440_BASE64, $encrypted[0]);
                $this->assertEquals(strtolower(self::PASSWORD_HEX), strtolower($encrypted[1]));
                $this->assertEquals(0, $encrypted[2]);
                $this->assertEquals('', $encrypted[3]);

                $decrypted = $cipher->decrypt(self::ENCRYPTED_PAYLOAD_RC440_BASE64, self::PASSWORD);
                $this->assertEquals(self::PAYLOAD, $decrypted);
            }
        });
    }
}
