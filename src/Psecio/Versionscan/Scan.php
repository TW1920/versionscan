<?php

namespace Psecio\Versionscan;

class Scan
{
    /**
     * Set of checks to run
     * @var array
     */
    private $checks = array();

    /**
     * The PHP version set for current checking
     * @var string
     */
    private $phpVersion = null;

    /**
     * Execute the scan
     *
     * @param type $phpVersion Optional PHP version
     * @param mixed $checks Check information (either an array or null)
     */
    public function execute($phpVersion = null, $checks = null)
    {
        if ($phpVersion === null) {
            $phpVersion = PHP_VERSION;
        }
        $this->setVersion($phpVersion);

        // pull in the Scan checks
        $this->loadChecks($checks);
        $this->runChecks();
    }

    /**
     * Set the current PHP version number
     *
     * @param string $version PHP version number
     */
    public function setVersion($version)
    {
        $this->phpVersion = $version;
    }

    /**
     * Get the current PHP version setting
     *
     * @return string PHP version number
     */
    public function getVersion()
    {
        return $this->phpVersion;
    }

    /**
     * Load the checks
     *     If null is given as input, it loads from the file
     *     If an array is given, it uses that data
     *
     * @param mixed $checks Check information
     * @return object Configuration loaded as an object
     */
    public function loadChecks($checks = null)
    {
        if ($checks === null) {
            // pull in the Scan checks
            $path = __DIR__.'/checks.json';
            if (is_file($path)) {
                $checks = @json_decode(file_get_contents($path));
                if ($checks === false) {
                    throw new Exception('Invalid check configuration');
                }
                $this->setChecks($checks->checks);
            } else {
                throw new Exception('Could not load check file '.$path);
            }
        } elseif (is_array($checks)) {
            $this->setChecks($checks);
        }
    }

    /**
     * Set the results of the check evaluation
     *
     * @param array $checks Set of check evaluation results
     */
    public function setChecks(array $checks)
    {
        $this->checks = array();

        foreach ($checks as $index => $check) {
            if (is_array($check)) {
                $check = new \Psecio\Versionscan\Check($check);
            }
            $this->checks[] = $check;
        }
    }

    /**
     * Get the current check result set
     *
     * @return array Check results
     */
    public function getChecks()
    {
        return $this->checks;
    }

    /**
     * Execute the checks to get pass/fail status
     */
    public function runChecks()
    {
        $checks = $this->getChecks();
        foreach ($checks as $index => $check) {
            $result = $checks[$index]->isVulnerable($this->getVersion());
            $checks[$index]->setResult($result);
        }
        $this->setChecks($checks);
    }
}