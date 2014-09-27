<?php

namespace Psecio\Versionscan;

use \InvalidArgumentException;

class Patch
{
    /**
     * Patch version
     * @var string
     */
    private $version = null;

    /**
     * CVEs that are patched
     * @var string
     */
    private $patched = array();

    /**
     * Init the check object with optional check data
     *
     * @param type $checkData Set of data to assign to the check
     */
    public function __construct($patchData = null)
    {
        if ($patchData !== null) {
            $this->setData($patchData);
        }
    }

    /**
     * Assign the patch data to the current object
     *
     * @param array $patchData Check data
     */
    public function setData($patchData)
    {
        $patchData = (is_object($patchData))
            ? get_object_vars($patchData) : $patchData;

        foreach ($patchData as $key => $data) {
            $this->$key = $data;
        }
    }

    /**
     * Get the release for the patch
     *
     * @return string release
     */
    public function getRelease()
    {
        return $this->release;
    }

    /**
     * Get the CVE patchs
     *
     * @return string version
     */
    public function getPatched()
    {
        return $this->patched;
    }
}