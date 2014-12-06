<?php

namespace Psecio\Versionscan;

class ScanTest extends \PHPUnit_Framework_TestCase
{
    private $scan = null;

    public function setUp()
    {
        $this->scan = new Scan();
    }

    /**
     * Check the getter/setter for the PHP version
     *
     * @covers \Psecio\Versionscan\Scan::__construct
     * @covers \Psecio\Versionscan\Scan::setVersion
     * @covers \Psecio\Versionscan\Scan::getVersion
     */
    public function testVersionGetterSetter()
    {
        $phpVersion = '5.2.12';
        $this->scan->setVersion($phpVersion);

        $this->assertEquals(
            $this->scan->getVersion(),
            $phpVersion
        );
    }

    /**
     * Verify that the checks are corrected loaded
     *
     * @covers \Psecio\Versionscan\Scan::__construct
     * @covers \Psecio\Versionscan\Scan::setChecks
     * @covers \Psecio\Versionscan\Scan::getChecks
     * @covers \Psecio\Versionscan\Check::__construct
     * @covers \Psecio\Versionscan\Check::setData
     * @covers \Psecio\Versionscan\Check::getCveId
     */
    public function testSetChecksArray()
    {
        $checks = array(
            array(
                'cveid' => 'CVE-1234',
                'summary' => 'This is a test',
                'fixVersions' => (object)array(
                    'base' => array('5.4.0')
                )
            )
        );
        $this->scan->setChecks($checks);

        $checks = $this->scan->getChecks();
        $this->assertTrue(is_object($checks[0]));

        $cveId = $checks[0]->getCveId();
        $this->assertTrue($cveId !== null);
        $this->assertEquals($cveId, 'CVE-1234');
    }

    /**
     * Check the setting of the version when the scan is initiated
     *
     * @covers \Psecio\Versionscan\Scan::__construct
     * @covers \Psecio\Versionscan\Scan::setVersion
     * @covers \Psecio\Versionscan\Scan::getVersion
     * @covers \Psecio\Versionscan\Scan::loadChecks
     * @covers \Psecio\Versionscan\Scan::loadPatches
     * @covers \Psecio\Versionscan\Scan::addPatches
     * @covers \Psecio\Versionscan\Patch::__construct
     * @covers \Psecio\Versionscan\Patch::setData
     * @covers \Psecio\Versionscan\Patch::getRelease
     * @covers \Psecio\Versionscan\Scan::setChecks
     * @covers \Psecio\Versionscan\Scan::getChecks
     * @covers \Psecio\Versionscan\Scan::runChecks
     * @covers \Psecio\Versionscan\Scan::getPatches
     * @covers \Psecio\Versionscan\Scan::isPatched
     * @covers \Psecio\Versionscan\Scan::execute
     */
    public function testSetVersionOnInit()
    {
        $phpVersion = '5.4.1';
        $scan = new Scan();
        $scan->execute($phpVersion, array());

        $this->assertEquals(
            $scan->getVersion(),
            $phpVersion
        );
    }

    /**
     * Check that the value for PHP_VERSION is returned by default
     *
     * @covers \Psecio\Versionscan\Scan::__construct
     * @covers \Psecio\Versionscan\Scan::execute
     * @covers \Psecio\Versionscan\Scan::getVersion
     * @covers \Psecio\Versionscan\Scan::setVersion
     * @covers \Psecio\Versionscan\Scan::loadChecks
     * @covers \Psecio\Versionscan\Scan::loadPatches
     * @covers \Psecio\Versionscan\Scan::addPatches
     * @covers \Psecio\Versionscan\Patch::__construct
     * @covers \Psecio\Versionscan\Patch::setData
     * @covers \Psecio\Versionscan\Patch::getRelease
     * @covers \Psecio\Versionscan\Scan::setChecks
     * @covers \Psecio\Versionscan\Scan::getChecks
     * @covers \Psecio\Versionscan\Scan::runChecks
     * @covers \Psecio\Versionscan\Scan::getPatches
     * @covers \Psecio\Versionscan\Scan::isPatched
     */
    public function testSetDefaultVersionOnInit()
    {
        $scan = new Scan();
        $scan->execute(null, array());

        $this->assertEquals(
            $scan->getVersion(),
            PHP_VERSION
        );
    }

    /**
     * Test that a run with valid criteria runs correctly
     *
     * @covers \Psecio\Versionscan\Scan::__construct
     * @covers \Psecio\Versionscan\Scan::execute
     * @covers \Psecio\Versionscan\Scan::getVersion
     * @covers \Psecio\Versionscan\Scan::setVersion
     * @covers \Psecio\Versionscan\Scan::loadChecks
     * @covers \Psecio\Versionscan\Scan::loadPatches
     * @covers \Psecio\Versionscan\Scan::addPatches
     * @covers \Psecio\Versionscan\Patch::__construct
     * @covers \Psecio\Versionscan\Patch::setData
     * @covers \Psecio\Versionscan\Patch::getRelease
     * @covers \Psecio\Versionscan\Scan::setChecks
     * @covers \Psecio\Versionscan\Scan::getChecks
     * @covers \Psecio\Versionscan\Scan::runChecks
     * @covers \Psecio\Versionscan\Scan::getPatches
     * @covers \Psecio\Versionscan\Scan::isPatched
     * @covers \Psecio\Versionscan\Check::__construct
     * @covers \Psecio\Versionscan\Check::setData
     * @covers \Psecio\Versionscan\Check::getCveId
     * @covers \Psecio\Versionscan\Check::getVersions
     * @covers \Psecio\Versionscan\Check::setResult
     * @covers \Psecio\Versionscan\Check::getResult
     * @covers \Psecio\Versionscan\Check::sortVersions
     * @covers \Psecio\Versionscan\Check::isVulnerable
     */
    public function testRunTestsValid()
    {
        $checks = array(
            array(
                'cveid' => 'CVE-1234',
                'summary' => 'This is a test',
                'fixVersions' => (object)array(
                    'base' => array('5.1.1')
                )
            )
        );
        $phpVersion = '5.4.1';

        $scan = new Scan();
        $scan->execute($phpVersion, $checks);

        $checks = $scan->getChecks();
        $this->assertFalse($checks[0]->getResult());
    }

    /**
     * Test that a run with valid criteria runs correctly (with a valid external rule file)
     *
     * @covers \Psecio\Versionscan\Scan::__construct
     * @covers \Psecio\Versionscan\Scan::execute
     * @covers \Psecio\Versionscan\Scan::getVersion
     * @covers \Psecio\Versionscan\Scan::setVersion
     * @covers \Psecio\Versionscan\Scan::loadChecks
     * @covers \Psecio\Versionscan\Scan::loadPatches
     * @covers \Psecio\Versionscan\Scan::addPatches
     * @covers \Psecio\Versionscan\Patch::__construct
     * @covers \Psecio\Versionscan\Patch::setData
     * @covers \Psecio\Versionscan\Patch::getRelease
     * @covers \Psecio\Versionscan\Scan::setChecks
     * @covers \Psecio\Versionscan\Scan::getChecks
     * @covers \Psecio\Versionscan\Scan::setCheckFile
     * @covers \Psecio\Versionscan\Scan::runChecks
     * @covers \Psecio\Versionscan\Scan::getPatches
     * @covers \Psecio\Versionscan\Scan::isPatched
     * @covers \Psecio\Versionscan\Check::__construct
     * @covers \Psecio\Versionscan\Check::setData
     * @covers \Psecio\Versionscan\Check::getCveId
     * @covers \Psecio\Versionscan\Check::getVersions
     * @covers \Psecio\Versionscan\Check::setResult
     * @covers \Psecio\Versionscan\Check::getResult
     * @covers \Psecio\Versionscan\Check::sortVersions
     * @covers \Psecio\Versionscan\Check::isVulnerable
     */
    public function testRunTestsFromFile()
    {
        $scan = new Scan();
        $file = __DIR__ . '/checks.json';
        $scan->setCheckFile($file);
        
        $scan->execute('5.4.33');
        $checks = $scan->getChecks();
        $this->assertFalse($checks[0]->getResult());

        $scan->execute('5.4.31');
        $checks = $scan->getChecks();
        $this->assertTrue($checks[0]->getResult());
    }

    /**
     * Test that a run fails (with a non-existant external rule file)
     *
     * @covers \Psecio\Versionscan\Scan::__construct
     * @covers \Psecio\Versionscan\Scan::execute
     * @covers \Psecio\Versionscan\Scan::setVersion
     * @covers \Psecio\Versionscan\Scan::loadChecks
     * @covers \Psecio\Versionscan\Scan::loadPatches
     * @covers \Psecio\Versionscan\Scan::addPatches
     * @covers \Psecio\Versionscan\Patch::__construct
     * @covers \Psecio\Versionscan\Patch::setData
     * @covers \Psecio\Versionscan\Patch::getRelease
     * @covers \Psecio\Versionscan\Scan::setCheckFile
     */
    public function testRunTestsFromMissingFileFail()
    {
        $phpVersion = '5.4.1';
        $file = __DIR__ . '/invalid_file';

        $scan = new Scan();
        $scan->setCheckFile($file);
        $this->setExpectedException('Exception', 'Could not load check file '.$file);
        $scan->execute($phpVersion);
    }

    /**
     * Test that a run fails (with an invalid external rule file)
     *
     * @covers \Psecio\Versionscan\Scan::__construct
     * @covers \Psecio\Versionscan\Scan::execute
     * @covers \Psecio\Versionscan\Scan::setVersion
     * @covers \Psecio\Versionscan\Scan::loadChecks
     * @covers \Psecio\Versionscan\Scan::loadPatches
     * @covers \Psecio\Versionscan\Scan::addPatches
     * @covers \Psecio\Versionscan\Patch::__construct
     * @covers \Psecio\Versionscan\Patch::setData
     * @covers \Psecio\Versionscan\Patch::getRelease
     * @covers \Psecio\Versionscan\Scan::setCheckFile
     */
    public function testRunTestsFromEmptyFileFail()
    {
        $phpVersion = '5.4.1';
        $file = __DIR__ . '/checks-invalid.json';

        $scan = new Scan();
        $scan->setCheckFile($file);
        $this->setExpectedException('Exception', 'Invalid check configuration');
        $scan->execute($phpVersion);
    }

    /**
     * Test that a run fails (with a non-existant patch file)
     *
     * @covers \Psecio\Versionscan\Scan::__construct
     * @covers \Psecio\Versionscan\Scan::setPatchFiles
     * @covers \Psecio\Versionscan\Scan::execute
     * @covers \Psecio\Versionscan\Scan::setVersion
     * @covers \Psecio\Versionscan\Scan::loadChecks
     * @covers \Psecio\Versionscan\Scan::loadPatches
     * @covers \Psecio\Versionscan\Scan::setChecks
     * @covers \Psecio\Versionscan\Check::__construct
     * @covers \Psecio\Versionscan\Check::setData
     * @covers \Psecio\Versionscan\Check::getCveId
     * @covers \Psecio\Versionscan\Check::getVersions
     * @covers \Psecio\Versionscan\Check::setResult
     * @covers \Psecio\Versionscan\Check::getResult
     * @covers \Psecio\Versionscan\Check::sortVersions
     * @covers \Psecio\Versionscan\Check::isVulnerable
     */
    public function testRunTestsFromMissingPatchFileFail() {
        $phpVersion = '5.4.1';
        $file = __DIR__ . '/invalid_file';

        $scan = new Scan();
        $scan->setPatchFiles(['invalid_os' => $file]);
        $this->setExpectedException('Exception', 'Could not load patch file '.$file);
        $scan->execute($phpVersion);
    }

    /**
     * Test that a run fails (with a non-existant patch file)
     *
     * @covers \Psecio\Versionscan\Scan::__construct
     * @covers \Psecio\Versionscan\Scan::setPatchFiles
     * @covers \Psecio\Versionscan\Scan::execute
     * @covers \Psecio\Versionscan\Scan::setVersion
     * @covers \Psecio\Versionscan\Scan::loadChecks
     * @covers \Psecio\Versionscan\Scan::loadPatches
     * @covers \Psecio\Versionscan\Scan::setChecks
     * @covers \Psecio\Versionscan\Check::__construct
     * @covers \Psecio\Versionscan\Check::setData
     * @covers \Psecio\Versionscan\Check::getCveId
     * @covers \Psecio\Versionscan\Check::getVersions
     * @covers \Psecio\Versionscan\Check::setResult
     * @covers \Psecio\Versionscan\Check::getResult
     * @covers \Psecio\Versionscan\Check::sortVersions
     * @covers \Psecio\Versionscan\Check::isVulnerable
     */
    public function testRunTestsFromEmptyPatchFileFail() {
        $phpVersion = '5.4.1';
        $file = __DIR__ . '/patches-invalid.json';

        $scan = new Scan();
        $scan->setPatchFiles(['invalid_os' => $file]);
        $this->setExpectedException('Exception', 'Invalid patch configuration');
        $scan->execute($phpVersion);
    }

    /**
     * Check custom patches properly determine if a version is patched against
     * a particular vulnerability
     *
     * @covers \Psecio\Versionscan\Scan::__construct
     * @covers \Psecio\Versionscan\Scan::execute
     * @covers \Psecio\Versionscan\Scan::getVersion
     * @covers \Psecio\Versionscan\Scan::setVersion
     * @covers \Psecio\Versionscan\Scan::loadChecks
     * @covers \Psecio\Versionscan\Scan::loadPatches
     * @covers \Psecio\Versionscan\Scan::addPatches
     * @covers \Psecio\Versionscan\Patch::__construct
     * @covers \Psecio\Versionscan\Patch::setData
     * @covers \Psecio\Versionscan\Patch::getRelease
     * @covers \Psecio\Versionscan\Patch::getPatched
     * @covers \Psecio\Versionscan\Scan::setChecks
     * @covers \Psecio\Versionscan\Scan::getChecks
     * @covers \Psecio\Versionscan\Scan::runChecks
     * @covers \Psecio\Versionscan\Scan::getPatches
     * @covers \Psecio\Versionscan\Scan::isPatched
     * @covers \Psecio\Versionscan\Check::__construct
     * @covers \Psecio\Versionscan\Check::setData
     * @covers \Psecio\Versionscan\Check::getCveId
     * @covers \Psecio\Versionscan\Check::getVersions
     * @covers \Psecio\Versionscan\Check::setResult
     * @covers \Psecio\Versionscan\Check::getResult
     * @covers \Psecio\Versionscan\Check::sortVersions
     * @covers \Psecio\Versionscan\Check::isVulnerable
     */
    public function testRunWithCustomPatch() {
        
        $scan = new Scan();
        $patches = [
            [
                "release" => "5.4.16-7.el6.1",
                "patched" => [
                    "CVE-1234"
                ]
            ]
        ];
        $checks = [
            [
                'cveid' => 'CVE-1234',
                'summary' => 'This is a test',
                'fixVersions' => [
                    '5.4.17'
                ]
            ],
            [
                'cveid' => 'CVE-1235',
                'summary' => 'This is a test',
                'fixVersions' => [
                    '5.4.15'
                ]
            ]
        ];

        // Ensure that normal patch fails
        $phpVersion = '5.4.16';
        $scan->execute($phpVersion, $checks, $patches);
        $checks = $scan->getChecks();
        $this->assertTrue($checks[0]->getResult());
        $this->assertFalse($checks[1]->getResult());

        // And ensure that a patched version passes
        $phpVersion = '5.4.16-7.el6.1';
        $scan->execute($phpVersion, $checks, $patches);
        $checks = $scan->getChecks();
        $this->assertFalse($checks[0]->getResult());
        $this->assertFalse($checks[1]->getResult());
    }
}