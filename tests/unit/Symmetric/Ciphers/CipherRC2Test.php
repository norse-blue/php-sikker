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
use NorseBlue\Sikker\Symmetric\Ciphers\CipherRC2;

class CipherRC2Test extends Unit
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
     * @var string An initialization vector.
     */
    const IV = 'Ygritte';

    /**
     * @var string The payload encrypted with RC2-128 and the password.
     */
    const ENCRYPTED_PAYLOAD_RC2128_BASE64 = 'SM+WGvFN64/3dQYde1xFduLWX1cZfudrtDHjzD+tlXwA6nDPHpH6jImg16xz/Upv';

    /**
     * @var string The payload encrypted with RC2-128, the password and the IV.
     */
    const ENCRYPTED_PAYLOAD_RC2128_BASE64_IV = '1B4X8/JG/8vkTSQBrmxhg7UzKwEx8jug5jCdMw7Bth4OCZK+y4ktBf6R4B5QllYg';

    /**
     * @var string The payload encrypted with RC2-64 and the password.
     */
    const ENCRYPTED_PAYLOAD_RC264_BASE64 = 'wYeukOGbqNSgGG4NvCqEn2K4zz4lU3FnropF1r67Q8+RjtarRv5cs8YhFEGaNLip';

    /**
     * @var string The payload encrypted with RC2-64, the password and the IV.
     */
    const ENCRYPTED_PAYLOAD_RC264_BASE64_IV = 'nyvfRXbLYeatdG+F9CvSEH+tfbGgCKyWxYKtOVO7LkXBmAb/3XgmJTvwu6g7YZXA';

    /**
     * @var string The payload encrypted with RC2-40 and the password.
     */
    const ENCRYPTED_PAYLOAD_RC240_BASE64 = '6CRH595DNNg8lleor/pIAcbFOI3dpdyh+q4ODH/sBmyBuleJrjxEJc3JqlAklHBq';

    /**
     * @var string The payload encrypted with RC2-40, the password and the IV.
     */
    const ENCRYPTED_PAYLOAD_RC240_BASE64_IV = 'EG3f/9elcQHJ+F9CKWkF91TPVPZRjWMmsa/GRPXfsSlFKPIIllrG1kILkhSxob6Z';

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
            $cipher = new CipherRC2(998);
        });
    }

    /**
     * Test incorrect mode
     */
    public function testIncorrectMode()
    {
        $this->specify('', function () {
            $this->expectException(InvalidArgumentException::class);
            $cipher = new CipherRC2(KeySize::_128, '', 0, 998);
        });
    }

    /**
     * Tests the type names
     */
    public function testEncryptionDecryption()
    {
        $this->specify('Encrypts and decrypts the payload with RC2-128', function () {
            if (extension_loaded('openssl') && CipherMethod::isAvailable(CipherMethod::RC2)) {
                $cipher = new CipherRC2(KeySize::_128);
                $encrypted = $cipher->encrypt(self::PAYLOAD, self::PASSWORD);
                $this->assertInternalType('array', $encrypted);
                $this->assertEquals(5, count($encrypted));
                $this->assertEquals(self::ENCRYPTED_PAYLOAD_RC2128_BASE64, $encrypted[0]);
                $this->assertEquals(strtolower(self::PASSWORD_HEX), strtolower($encrypted[1]));
                $this->assertEquals(0, $encrypted[2]);
                $this->assertEquals('', $encrypted[3]);

                $decrypted = $cipher->decrypt(self::ENCRYPTED_PAYLOAD_RC2128_BASE64, self::PASSWORD);
                $this->assertEquals(self::PAYLOAD, $decrypted);
            }
        });

        $this->specify('Encrypts and decrypts the payload with RC2-128 and an IV.', function () {
            if (extension_loaded('openssl') && CipherMethod::isAvailable(CipherMethod::RC2)) {
                $cipher = new CipherRC2(KeySize::_128, self::IV);
                $encrypted = $cipher->encrypt(self::PAYLOAD, self::PASSWORD);
                $this->assertInternalType('array', $encrypted);
                $this->assertEquals(5, count($encrypted));
                $this->assertEquals(self::ENCRYPTED_PAYLOAD_RC2128_BASE64_IV, $encrypted[0]);
                $this->assertEquals(strtolower(self::PASSWORD_HEX), strtolower($encrypted[1]));
                $this->assertEquals(0, $encrypted[2]);
                $this->assertEquals(self::IV, $encrypted[3]);

                $decrypted = $cipher->decrypt(self::ENCRYPTED_PAYLOAD_RC2128_BASE64_IV, self::PASSWORD);
                $this->assertEquals(self::PAYLOAD, $decrypted);
            }
        });

        $this->specify('Encrypts and decrypts the payload with RC2-64', function () {
            if (extension_loaded('openssl') && CipherMethod::isAvailable(CipherMethod::RC2_64)) {
                $cipher = new CipherRC2(KeySize::_64);
                $encrypted = $cipher->encrypt(self::PAYLOAD, self::PASSWORD);
                $this->assertInternalType('array', $encrypted);
                $this->assertEquals(5, count($encrypted));
                $this->assertEquals(self::ENCRYPTED_PAYLOAD_RC264_BASE64, $encrypted[0]);
                $this->assertEquals(strtolower(self::PASSWORD_HEX), strtolower($encrypted[1]));
                $this->assertEquals(0, $encrypted[2]);
                $this->assertEquals('', $encrypted[3]);

                $decrypted = $cipher->decrypt(self::ENCRYPTED_PAYLOAD_RC264_BASE64, self::PASSWORD);
                $this->assertEquals(self::PAYLOAD, $decrypted);
            }
        });

        $this->specify('Encrypts and decrypts the payload with RC2-64 and an IV.', function () {
            if (extension_loaded('openssl') && CipherMethod::isAvailable(CipherMethod::RC2_64)) {
                $cipher = new CipherRC2(KeySize::_64, self::IV);
                $encrypted = $cipher->encrypt(self::PAYLOAD, self::PASSWORD);
                $this->assertInternalType('array', $encrypted);
                $this->assertEquals(5, count($encrypted));
                $this->assertEquals(self::ENCRYPTED_PAYLOAD_RC264_BASE64_IV, $encrypted[0]);
                $this->assertEquals(strtolower(self::PASSWORD_HEX), strtolower($encrypted[1]));
                $this->assertEquals(0, $encrypted[2]);
                $this->assertEquals(self::IV, $encrypted[3]);

                $decrypted = $cipher->decrypt(self::ENCRYPTED_PAYLOAD_RC264_BASE64_IV, self::PASSWORD);
                $this->assertEquals(self::PAYLOAD, $decrypted);
            }
        });

        $this->specify('Encrypts and decrypts the payload with RC2-40', function () {
            if (extension_loaded('openssl') && CipherMethod::isAvailable(CipherMethod::RC2_40)) {
                $cipher = new CipherRC2(KeySize::_40);
                $encrypted = $cipher->encrypt(self::PAYLOAD, self::PASSWORD);
                $this->assertInternalType('array', $encrypted);
                $this->assertEquals(5, count($encrypted));
                $this->assertEquals(self::ENCRYPTED_PAYLOAD_RC240_BASE64, $encrypted[0]);
                $this->assertEquals(strtolower(self::PASSWORD_HEX), strtolower($encrypted[1]));
                $this->assertEquals(0, $encrypted[2]);
                $this->assertEquals('', $encrypted[3]);

                $decrypted = $cipher->decrypt(self::ENCRYPTED_PAYLOAD_RC240_BASE64, self::PASSWORD);
                $this->assertEquals(self::PAYLOAD, $decrypted);
            }
        });

        $this->specify('Encrypts and decrypts the payload with RC2-40 and an IV.', function () {
            if (extension_loaded('openssl') && CipherMethod::isAvailable(CipherMethod::RC2_40)) {
                $cipher = new CipherRC2(KeySize::_40, self::IV);
                $encrypted = $cipher->encrypt(self::PAYLOAD, self::PASSWORD);
                $this->assertInternalType('array', $encrypted);
                $this->assertEquals(5, count($encrypted));
                $this->assertEquals(self::ENCRYPTED_PAYLOAD_RC240_BASE64_IV, $encrypted[0]);
                $this->assertEquals(strtolower(self::PASSWORD_HEX), strtolower($encrypted[1]));
                $this->assertEquals(0, $encrypted[2]);
                $this->assertEquals(self::IV, $encrypted[3]);

                $decrypted = $cipher->decrypt(self::ENCRYPTED_PAYLOAD_RC240_BASE64_IV, self::PASSWORD);
                $this->assertEquals(self::PAYLOAD, $decrypted);
            }
        });
    }
}
