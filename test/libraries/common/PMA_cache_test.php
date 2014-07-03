<?php
/* vim: set expandtab sw=4 ts=4 sts=4: */
/**
 * Test for caching data in session
 *
 * @package PhpMyAdmin-test
 * @group common.lib-tests
 */

/*
 * Include to test.
 */
require_once 'libraries/Util.class.php';

/**
 * Test for caching data in session
 *
 * @package PhpMyAdmin-test
 * @group common.lib-tests
 */
class PMA_Cache_Test extends PHPUnit_Framework_TestCase
{

    /**
     * @var array temporary variable for globals array
     */
    protected $tmpGlobals;

    /**
     * @var array temporary variable for session array
     */
    protected $tmpSession;

    /**
     * storing globals and session
     *
     * @return void
     */
    public function setUp()
    {
        $this->tmpGlobals = $GLOBALS;
        $this->tmpSession = $_SESSION;
    }

    /**
     * Test if cached data is available after set
     *
     * @return void
     */
    public function testCacheExists()
    {
        $GLOBALS['server'] = 'server';
        PMA_Util::cacheSet('test_data', 5, null);
        PMA_Util::cacheSet('test_data_2', 5, null);

        $this->assertTrue(PMA_Util::cacheExists('test_data', null));
        $this->assertTrue(PMA_Util::cacheExists('test_data_2', 'server'));
        $this->assertFalse(PMA_Util::cacheExists('fake_data_2', null));
    }

    /**
     * Test if PMA_Util::cacheGet does not return data for non existing cache entries
     *
     * @return void
     */
    public function testCacheGet()
    {
        $GLOBALS['server'] = 'server';
        PMA_Util::cacheSet('test_data', 5, null);
        PMA_Util::cacheSet('test_data_2', 5, null);

        $this->assertNotNull(PMA_Util::cacheGet('test_data', null));
        $this->assertNotNull(PMA_Util::cacheGet('test_data_2', 'server'));
        $this->assertNull(PMA_Util::cacheGet('fake_data_2', null));
    }

    /**
     * Test retrieval of cached data
     *
     * @return void
     */
    public function testCacheSetGet()
    {
        $GLOBALS['server'] = 'server';
        PMA_Util::cacheSet('test_data', 25, null);

        PMA_Util::cacheSet('test_data', 5, null);
        $this->assertEquals(5, $_SESSION['cache']['server_server']['test_data']);
        PMA_Util::cacheSet('test_data_3', 3, null);
        $this->assertEquals(3, $_SESSION['cache']['server_server']['test_data_3']);
    }

    /**
     * Test clearing cached values
     *
     * @return void
     */
    public function testCacheUnSet()
    {
        $GLOBALS['server'] = 'server';
        PMA_Util::cacheSet('test_data', 25, null);
        PMA_Util::cacheSet('test_data_2', 25, null);

        PMA_Util::cacheUnset('test_data', null);
        $this->assertArrayNotHasKey('test_data', $_SESSION['cache']['server_server']);
        PMA_Util::cacheUnset('test_data_2', null);
        $this->assertArrayNotHasKey('test_data_2', $_SESSION['cache']['server_server']);
    }

    /**
     * Test clearing user cache
     *
     * @return void
     */
    public function testClearUserCache()
    {
        $GLOBALS['server'] = 'server';
        PMA_Util::cacheSet('is_superuser', 'yes', null);
        $this->assertEquals('yes', $_SESSION['cache']['server_server']['is_superuser']);

        PMA_Util::clearUserCache();
        $this->assertArrayNotHasKey('is_superuser', $_SESSION['cache']['server_server']);
    }
}
?>
