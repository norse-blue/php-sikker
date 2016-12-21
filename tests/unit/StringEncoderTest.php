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

namespace NorseBlue\Sikker\Tests\OpenSSL;

use Codeception\Specify;
use Codeception\Util\Debug;
use Codeception\Test\Unit;
use InvalidArgumentException;
use NorseBlue\Sikker\StringEncoder;

class StringEncoderTest extends Unit
{
    use Specify;

    /**
     * @var string Helper payload.
     */
    const PAYLOAD = 'You know nothing Jon Snow! Winter is coming!';

    /**
     * @var string Helper payload as hex.
     */
    const PAYLOAD_HEX = '596f75206b6e6f77206e6f7468696e67204a6f6e20536e6f77212057696e74657220697320636f6d696e6721';

    /**
     * @var string Helper payload as base64.
     */
    const PAYLOAD_BASE64 = 'WW91IGtub3cgbm90aGluZyBKb24gU25vdyEgV2ludGVyIGlzIGNvbWluZyE=';

    protected function _after()
    {
    }

    protected function _before()
    {
    }

    // tests

    /**
     * Tests the raw-hex encoding functions.
     */
    public function testRawHexEncoding()
    {
        $this->specify('Converts the payload to hex and then to raw.', function () {
            $hex = StringEncoder::rawToHex(self::PAYLOAD);
            Debug::debug(sprintf('Hex string: %s', $hex));
            $this->assertEquals(self::PAYLOAD_HEX, $hex);

            $raw = StringEncoder::hexToRaw($hex);
            Debug::debug(sprintf('Raw string: %s', $raw));
            $this->assertEquals(self::PAYLOAD, $raw);
        });
    }

    /**
     * Tests the raw-base64 encoding functions.
     */
    public function testRawBase64Encoding()
    {
        $this->specify('Converts the payload to base64 and then to raw.', function () {
            $base64 = StringEncoder::rawToBase64(self::PAYLOAD);
            Debug::debug(sprintf('Hex string: %s', $base64));
            $this->assertEquals(self::PAYLOAD_BASE64, $base64);

            $raw = StringEncoder::base64ToRaw($base64);
            Debug::debug(sprintf('Raw string: %s', $raw));
            $this->assertEquals(self::PAYLOAD, $raw);

            $this->expectException(InvalidArgumentException::class);
            StringEncoder::base64ToRaw('Non-base64 encoded string should throw and exception!!!');
        });
    }
}
