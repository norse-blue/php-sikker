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

namespace NorseBlue\Sikker\Tests\Entropy;

use Codeception\Specify;
use Codeception\Test\Unit;
use Mockery;
use NorseBlue\Sikker\Entropy\Adapters\EntropyAdapter;
use NorseBlue\Sikker\Entropy\Entropy;

class EntropyTest extends Unit
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
     * Tests getter and setter of the EntropyAdapter property.
     */
    public function testGetSetAdapter()
    {
        $this->specify('Sets and gets the EntropyAdapter correctly.', function () {
            $entropyAdapter = Mockery::mock(EntropyAdapter::class);
            $entropyAdapterNew = Mockery::mock(EntropyAdapter::class);
            $entropy = new Entropy($entropyAdapter);
            $this->assertSame($entropyAdapter, $entropy->getAdapter());
            $entropy->setAdapter($entropyAdapterNew);
            $this->assertNotSame($entropyAdapter, $entropy->getAdapter());
            $this->assertSame($entropyAdapterNew, $entropy->getAdapter());
        });
    }

    /**
     * Tests the splitChars function.
     */
    public function testSplitChars()
    {
        $this->specify('Split the string into an array of chars.', function () {
            $str = 'Jon Snow';
            $this->assertEquals(['J', 'o', 'n', ' ', 'S', 'n', 'o', 'w'], Entropy::splitChars($str));
        });

        $this->specify('Split the unicode string into an array of chars.', function () {
            $str = 'Jön Snôw';
            $this->assertEquals(['J', 'ö', 'n', ' ', 'S', 'n', 'ô', 'w'], Entropy::splitChars($str));
        });
    }

    /**
     * Tests the charCounts function.
     */
    public function testCharCounts()
    {
        $this->specify('Get the char count in a non-repeating char string.', function () {
            $str = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345';
            $charsCount = Entropy::charCounts($str);
            $this->assertEquals(32, count($charsCount));
            $this->assertEquals([
                'A' => 1,
                'B' => 1,
                'C' => 1,
                'D' => 1,
                'E' => 1,
                'F' => 1,
                'G' => 1,
                'H' => 1,
                'I' => 1,
                'J' => 1,
                'K' => 1,
                'L' => 1,
                'M' => 1,
                'N' => 1,
                'O' => 1,
                'P' => 1,
                'Q' => 1,
                'R' => 1,
                'S' => 1,
                'T' => 1,
                'U' => 1,
                'V' => 1,
                'W' => 1,
                'X' => 1,
                'Y' => 1,
                'Z' => 1,
                0 => 1,
                1 => 1,
                2 => 1,
                3 => 1,
                4 => 1,
                5 => 1
            ], $charsCount);
        });

        $this->specify('Get the char count in a some-repeating char string.', function () {
            $str = 'CnRwh61ygUUEAs8o2JphrOGrfZ8sxSLr';
            $charsCount = Entropy::charCounts($str);
            $this->assertEquals(26, count($charsCount));
            $this->assertEquals([
                'C' => 1,
                'n' => 1,
                'R' => 1,
                'w' => 1,
                'h' => 2,
                6 => 1,
                1 => 1,
                'y' => 1,
                'g' => 1,
                'U' => 2,
                'E' => 1,
                'A' => 1,
                's' => 2,
                8 => 2,
                'o' => 1,
                2 => 1,
                'J' => 1,
                'p' => 1,
                'r' => 3,
                'O' => 1,
                'G' => 1,
                'f' => 1,
                'Z' => 1,
                'x' => 1,
                'S' => 1,
                'L' => 1
            ], $charsCount);
        });

        $this->specify('Get the char count in an all-repeating char string.', function () {
            $str = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
            $charsCount = Entropy::charCounts($str);
            $this->assertEquals(1, count($charsCount));
            $this->assertEquals(['A' => 32], $charsCount);
        });

        $this->specify('Get the char count in an empty string.', function () {
            $str = '';
            $charsCount = Entropy::charCounts($str);
            $this->assertEquals(0, count($charsCount));
            $this->assertEquals([], $charsCount);
        });

        $this->specify('Get the char count in a string with upper and lower case characters.', function () {
            $str = 'AaEeIiOoUuA';
            $charsCount = Entropy::charCounts($str);
            $this->assertEquals(10, count($charsCount));
            $this->assertEquals([
                'A' => 2,
                'a' => 1,
                'E' => 1,
                'e' => 1,
                'I' => 1,
                'i' => 1,
                'O' => 1,
                'o' => 1,
                'U' => 1,
                'u' => 1
            ], $charsCount);
        });

        $this->specify('Get the char count in a string with unicode characters.', function () {
            $str = 'áéíóúäëïöü';
            $charsCount = Entropy::charCounts($str);
            $this->assertEquals(10, count($charsCount));
            $this->assertEquals([
                'á' => 1,
                'é' => 1,
                'í' => 1,
                'ó' => 1,
                'ú' => 1,
                'ä' => 1,
                'ë' => 1,
                'ï' => 1,
                'ö' => 1,
                'ü' => 1
            ], $charsCount);
        });
    }

    /**
     * Tests the charDistances function.
     */
    public function testCharDistances()
    {
        $this->specify('Calculates the degrees of separation between characters.', function () {
            $str = 'You know nothing Jon Snow! Winter is coming!!';
            $this->assertEquals([
                'o' => [0 => 5, 1 => 4, 2 => 8, 3 => 5, 4 => 15,],
                ' ' => [0 => 5, 1 => 8, 2 => 4, 3 => 6, 4 => 7, 5 => 3,],
                'n' => [0 => 4, 1 => 5, 2 => 5, 3 => 3, 4 => 7, 5 => 12,],
                'w' => [0 => 17,],
                't' => [0 => 19,],
                'i' => [0 => 15, 1 => 6, 2 => 6,],
                'g' => [0 => 27,],
                '!' => [0 => 18, 1 => 1]
            ], Entropy::charDistances($str));
        });

        $this->specify('Calculates the degrees of separation between characters (return all chars).', function () {
            $str = 'You know nothing Jon Snow! Winter is coming!!';
            $this->assertEquals([
                'Y' => [],
                'o' => [0 => 5, 1 => 4, 2 => 8, 3 => 5, 4 => 15,],
                'u' => [],
                ' ' => [0 => 5, 1 => 8, 2 => 4, 3 => 6, 4 => 7, 5 => 3,],
                'k' => [],
                'n' => [0 => 4, 1 => 5, 2 => 5, 3 => 3, 4 => 7, 5 => 12,],
                'w' => [0 => 17,],
                't' => [0 => 19,],
                'h' => [],
                'i' => [0 => 15, 1 => 6, 2 => 6,],
                'g' => [0 => 27,],
                'J' => [],
                'S' => [],
                '!' => [0 => 18, 1 => 1],
                'W' => [],
                'e' => [],
                'r' => [],
                's' => [],
                'c' => [],
                'm' => []
            ], Entropy::charDistances($str, true));
        });

        $this->specify('Calculates the degrees of separation between characters in an empty string.', function () {
            $str = '';
            $this->assertEquals([], Entropy::charDistances($str));
        });
    }

    /**
     * Tests the repeatFactor function.
     */
    public function testRepeatFactor()
    {
        $this->specify('Calculates the char repeatability factor on a non-repeats string.', function () {
            $str = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345';
            $this->assertEquals(0, Entropy::repeatFactor($str));     //  No repeats
        });

        $this->specify('Calculates the char repeatability factor on a some-repeats string.', function () {
            $str = 'CnRwh61ygUUEAs8o2JphrOGrfZ8sxSLr';
            $this->assertEquals(0.34375, Entropy::repeatFactor($str));      //  6(repeats) / 32(length)
        });

        $this->specify('Calculates the char repeatability factor on a all-repeats string.', function () {
            $str = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
            $this->assertEquals(1, Entropy::repeatFactor($str));     // All repeats
        });

        $this->specify('Calculates the char repeatability factor on an almost-all-repeats string.', function () {
            $str = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB';
            $this->assertEquals(0.96875, Entropy::repeatFactor($str));     // All repeats
        });

        $this->specify('Calculates the char repeatability factor on an empty string.', function () {
            $str = '';
            $this->assertEquals(0, Entropy::repeatFactor($str));     // All repeats
        });

        $this->specify('Calculates the char repeatability factor on a string with upper and lower case characters.',
            function () {
                $str = 'AaEeIiOoUuA';
                $this->assertEquals(0.1818181818, Entropy::repeatFactor($str));     // Upper and lower case repeats
            });

        $this->specify('Calculates the char repeatability factor on a string with unicode characters.', function () {
            $str = 'áéíóúäëïöüá';
            $this->assertEquals(0.1818181818, Entropy::repeatFactor($str));     // Unicode chars repeats
        });
    }

    /**
     * Tests the spatialDimension function.
     * @see https://pthree.org/2011/03/07/strong-passwords-need-entropy/ Strong Passwords NEED Entropy by Aaron Toponce
     */
    public function testSpatialDimension()
    {
        $this->specify('Gets the spatial dimension of an only-digits string.', function () {
            $str = '6541981';
            $this->assertEquals(10, Entropy::spatialDimension($str));
        });

        $this->specify('Gets the spatial dimension of an only-lowercase letters string.', function () {
            $str = 'password';
            $this->assertEquals(26, Entropy::spatialDimension($str));
        });

        $this->specify('Gets the spatial dimension of an only-uppercase letters string.', function () {
            $str = 'MYSECRETSTRING';
            $this->assertEquals(26, Entropy::spatialDimension($str));
        });

        $this->specify('Gets the spatial dimension of an only-symbols string.', function () {
            $str = '&_\'./*_:;,.\\';
            $this->assertEquals(32, Entropy::spatialDimension($str));
        });

        $this->specify('Gets the spatial dimension of a string containing lowercase and uppercase letters character classes.',
            function () {
                $str = 'RedSox';
                $this->assertEquals(52, Entropy::spatialDimension($str));
            });

        $this->specify('Gets the spatial dimension of a string containing all character classes.', function () {
            $str = 'B1gbRother|$alw4ysriGHt!?';
            $this->assertEquals(94, Entropy::spatialDimension($str));
        });

        $this->specify('Gets the spatial dimension of a string containing lowercase letters and digits character classes.',
            function () {
                $str = 'deer2010';
                $this->assertEquals(36, Entropy::spatialDimension($str));
            });
    }

    /**
     * Tests the estimate function with the default adapter.
     * This implementation of the estimation of entropy does not round up the values, instead it does a floor
     * (it "fails" to the secure side) so some values are different form the ones in Aaron's page.
     * In particular two cases are also miscalculated in the page, this are: '!Aaron08071999Keri|' and '4pRte!aii@3',
     * in both cases the length of the string is wrong.
     *
     * @see https://pthree.org/2011/03/07/strong-passwords-need-entropy/ Strong Passwords NEED Entropy by Aaron Toponce
     */
    public function testEstimate()
    {
        $this->specify('Estimate the entropy of the given string \'password\'', function () {
            $str = 'password';
            $entropy = new Entropy();
            $this->assertEquals(37, $entropy->estimate($str));
        });

        $this->specify('Estimate the entropy of the given string \'RedSox\'', function () {
            $str = 'RedSox';
            $entropy = new Entropy();
            $this->assertEquals(34, $entropy->estimate($str));
        });

        $this->specify('Estimate the entropy of the given string \'B1gbRother|$alw4ysriGHt!?\'', function () {
            $str = 'B1gbRother|$alw4ysriGHt!?';
            $entropy = new Entropy();
            $this->assertEquals(163, $entropy->estimate($str));
        });

        $this->specify('Estimate the entropy of the given string \'deer2010\'', function () {
            $str = 'deer2010';
            $entropy = new Entropy();
            $this->assertEquals(41, $entropy->estimate($str));
        });

        $this->specify('Estimate the entropy of the given string \'l33th4x0r\'', function () {
            $str = 'l33th4x0r';
            $entropy = new Entropy();
            $this->assertEquals(46, $entropy->estimate($str));
        });

        $this->specify('Estimate the entropy of the given string \'!Aaron08071999Keri|\'', function () {
            $str = '!Aaron08071999Keri|';
            $entropy = new Entropy();
            $this->assertEquals(124, $entropy->estimate($str));
        });

        $this->specify('Estimate the entropy of the given string \'PassWord\'', function () {
            $str = 'PassWord';
            $entropy = new Entropy();
            $this->assertEquals(45, $entropy->estimate($str));
        });

        $this->specify('Estimate the entropy of the given string \'4pRte!aii@3\'', function () {
            $str = '4pRte!aii@3';
            $entropy = new Entropy();
            $this->assertEquals(72, $entropy->estimate($str));
        });
    }
}