<?php

namespace Psecio\Versionscan;

use \Exception;

class Scan
{
    /**
     * Set of checks to run
     * @var array
     */
    private $checks = array();

    /**
     * Set of patches to run
     * @var array
     */
    private $patches = array();

    /**
     * The PHP version set for current checking
     * @var string
     */
    private $phpVersion = null;

    /**
     * File to load checks from
     * @var string
     */
    private $checkFile;

    /**
     * File to load patches from
     * @var string
     */
    private $patchFiles;

    /**
     * Setup checks file path
     */
    public function __construct()
    {
        $this->checkFile = __DIR__.'/checks.json';
        $this->patchFiles = array(
            'ubuntu' => __DIR__ . '/ubuntu-lts.json',
            'debian' => __DIR__ . '/debian-releases.json',
            'redhat' => __DIR__ . '/redhat-releases.json'
        );
    }

    /**
     * Execute the scan
     *
     * @param type $phpVersion Optional PHP version
     * @param mixed $checks Check information (either an array or null)
     * @param mixed $patches Patch information (either an array or null)
     */
    public function execute($phpVersion = null, $checks = null, $patches = null)
    {
        if ($phpVersion === null) {
            $phpVersion = PHP_VERSION;
        }
        $this->setVersion($phpVersion);

        // pull in the Scan checks
        $this->loadChecks($checks);
        $this->loadPatches($patches);
        $this->runChecks();
    }

    /**
     * Set the current PHP version number
     *
     * @param string $version PHP version number
     */
    public function setVersion($version)
    {
        // We need to remove any prepending php rubbish
        $this->phpVersion = trim(str_replace('php', '', $version), '-');
    }

    /**
     * Over ride our patch files
     * 
     * @param array $patchFiles The patch files you wish to use
     */
    public function setPatchFiles(array $patchFiles)
    {
        $this->patchFiles = $patchFiles;
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
     * Is this a patched version of PHP?
     *
     * @return boolean
     */
    public function isPatched()
    {
        return preg_match('/ubuntu|deb|el\d|stronghold|php-\d\.\d+\.\d+-\d+\.\d+/i', $this->getVersion());
    }

    /**
     * Set check file
     *
     * @param string $checkFile File to use for scan rules
     */
    public function setCheckFile($checkFile)
    {
        $this->checkFile = $checkFile;
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
            if (is_file($this->checkFile)) {
                $checks = @json_decode(file_get_contents($this->checkFile));
                if (!$checks) {
                    throw new Exception('Invalid check configuration');
                }
                $this->setChecks($checks->checks);
            } else {
                throw new Exception('Could not load check file '.$this->checkFile);
            }
        } elseif (is_array($checks)) {
            $this->setChecks($checks);
        }
    }

    /**
     * Load the patches
     *     If null is given as input, it loads from the file
     *     If an array is given, it uses that data
     *
     * @param mixed $patches Patch information
     * @return object Configuration loaded as an object
     */
    public function loadPatches($patches = null)
    {
        if ($patches === null) {
            // pull in the Patch checks
            foreach ($this->patchFiles as $set => $patchFile)
            {
                if (is_file($patchFile)) {
                    $patches = @json_decode(file_get_contents($patchFile));
                    if (!$patches) {
                        throw new Exception('Invalid patch configuration');
                    }
                    $this->addPatches($set, $patches->patches);
                } else {
                    throw new Exception('Could not load patch file '.$patchFile);
                }    
            }
        } elseif (is_array($patches)) {
            $this->addPatches('custom', $patches);
        }
    }

    /**
     * Set the results of the check evaluation
     *
     * @param string $set The name of the patch set
     * @param array $patches Set of patches 
     */
    public function addPatches($set, array $patches)
    {
        $this->patches[$set] = array();
        foreach ($patches as $index => $patch) {
            $patch = new \Psecio\Versionscan\Patch($patch);
            $this->patches[$set][$patch->getRelease()] = $patch;
        }
    }

    /**
     * Get the current patch result set
     *
     * @return array Patch results
     */
    public function getPatches()
    {
        return $this->patches;
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
            $check = new \Psecio\Versionscan\Check($check);
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

        // Check if we have to mark patch CVEs off
        // First see if it fits within a patch
        if ($this->isPatched())
        {
            $vuln_patched = array();
            $version_partial = array_shift(explode('-', $this->getVersion()));
            foreach ($this->getPatches() as $set => $patches) {
                // Check each patch set
                $found = false;
                foreach ($patches as $version => $patch) {
                    if ($version == $this->getVersion()) {
                        // Use the rest of these patches to determine which vulnerabilities are resolved
                        $found = true;
                    }

                    $partial = array_shift(explode('-', $version));
                    if ($found && $partial == $version_partial) {
                        $vuln_patched = array_merge($vuln_patched, $patch->getPatched());
                    }
                }
            }
            $vuln_patched = array_unique($vuln_patched);

            foreach ($checks as $check) {
                // Ignore if not vulnerable
                if ($check->getResult() !== true) {
                    continue;
                }
                if (in_array($check->getCveId(), $vuln_patched)) {
                    //echo $check->getCveId() . " has been patched in this release (or earlier)\n";
                    $check->setResult(false);
                }
            }
        }

        $this->setChecks($checks);
    }
}