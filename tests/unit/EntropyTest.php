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

namespace NorseBlue\Sikker\Tests;

use Codeception\Specify;
use Codeception\Test\Unit;
use NorseBlue\Sikker\Entropy;

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
     * Tests the cars count function.
     */
    public function testCharsCount()
    {
        $this->specify('Get the char count in a non-repeating char string.', function () {
            $str = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345';
            $charsCount = Entropy::charsCount($str);
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
            $charsCount = Entropy::charsCount($str);
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
            $charsCount = Entropy::charsCount($str);
            $this->assertEquals(1, count($charsCount));
            $this->assertEquals(['A' => 32], $charsCount);
        });

        $this->specify('Get the char count in an empty string.', function () {
            $str = '';
            $charsCount = Entropy::charsCount($str);
            $this->assertEquals(0, count($charsCount));
            $this->assertEquals([], $charsCount);
        });
    }

    /**
     * Tests the repeatability factor calculation.
     */
    public function testCalculateRepeatabilityFactor()
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
    }
}