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

namespace NorseBlue\Sikker\Tests\Entropy\Adapters;

use Codeception\Specify;
use Codeception\Test\Unit;
use NorseBlue\Sikker\Entropy\Adapters\EntropyAdapterSimple;

class EntropyAdpaterSimpleTest extends Unit
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
     * Tests the estimateEntropy function.
     * This implementation of the estimation of entropy does not round up the values, instead it does a floor
     * (it "fails" to the secure side) so some values are different form the ones in Aaron's page.
     * In particular two cases are also miscalculated in the page, this are: '!Aaron08071999Keri|' and '4pRte!aii@3',
     * in both cases the length of the string is wrong.
     *
     * @see https://pthree.org/2011/03/07/strong-passwords-need-entropy/ Strong Passwords NEED Entropy by Aaron Toponce
     */
    public function testEstimateEntropy()
    {
        $this->specify('Estimate the entropy of the given string \'password\'', function () {
            $str = 'password';
            $entropyAdapter = new EntropyAdapterSimple();
            $this->assertEquals(37, $entropyAdapter->estimateEntropy($str));
        });

        $this->specify('Estimate the entropy of the given string \'RedSox\'', function () {
            $str = 'RedSox';
            $entropyAdapter = new EntropyAdapterSimple();
            $this->assertEquals(34, $entropyAdapter->estimateEntropy($str));
        });

        $this->specify('Estimate the entropy of the given string \'B1gbRother|$alw4ysriGHt!?\'', function () {
            $str = 'B1gbRother|$alw4ysriGHt!?';
            $entropyAdapter = new EntropyAdapterSimple();
            $this->assertEquals(163, $entropyAdapter->estimateEntropy($str));
        });

        $this->specify('Estimate the entropy of the given string \'deer2010\'', function () {
            $str = 'deer2010';
            $entropyAdapter = new EntropyAdapterSimple();
            $this->assertEquals(41, $entropyAdapter->estimateEntropy($str));
        });

        $this->specify('Estimate the entropy of the given string \'l33th4x0r\'', function () {
            $str = 'l33th4x0r';
            $entropyAdapter = new EntropyAdapterSimple();
            $this->assertEquals(46, $entropyAdapter->estimateEntropy($str));
        });

        $this->specify('Estimate the entropy of the given string \'!Aaron08071999Keri|\'', function () {
            $str = '!Aaron08071999Keri|';
            $entropyAdapter = new EntropyAdapterSimple();
            $this->assertEquals(124, $entropyAdapter->estimateEntropy($str));
        });

        $this->specify('Estimate the entropy of the given string \'PassWord\'', function () {
            $str = 'PassWord';
            $entropyAdapter = new EntropyAdapterSimple();
            $this->assertEquals(45, $entropyAdapter->estimateEntropy($str));
        });

        $this->specify('Estimate the entropy of the given string \'4pRte!aii@3\'', function () {
            $str = '4pRte!aii@3';
            $entropyAdapter = new EntropyAdapterSimple();
            $this->assertEquals(72, $entropyAdapter->estimateEntropy($str));
        });
    }
}