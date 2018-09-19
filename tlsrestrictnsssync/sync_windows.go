// Copyright 2018 Jeremy Rand.

// This file is part of tlsrestrictnss.
//
// tlsrestrictnss is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// tlsrestrictnss is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with tlsrestrictnss.  If not, see <https://www.gnu.org/licenses/>.

package tlsrestrictnsssync

import (
	"fmt"
	"sync"
	"time"

	"github.com/hlandau/xlog"
	"gopkg.in/hlandau/easyconfig.v1/cflag"

	"golang.org/x/sys/windows/registry"

	"github.com/namecoin/tlsrestrictnss"
)

var (
	flagGroup      = cflag.NewGroup(nil, "tlsrestrictnss")
	syncEnableFlag = cflag.Bool(flagGroup, "sync", false, "Update NSS "+
		"name constraints as new NSS CKBI versions are released.")
	versionRegistryKeyFlag = cflag.String(flagGroup, "regkey", "",
		"Registry key holding the version of the NSS CKBI "+
			"application.  (Required.)")
	nssDestDirFlag = cflag.String(flagGroup, "nss-dest-db-dir",
		"", "Directory to write NSS certs to.  (Required.)")
	nssCKBIDirFlag = cflag.String(flagGroup, "nss-ckbi-dir", "",
		"Directory containing "+tlsrestrictnss.NSSCKBIName+
			".  (Required.)")
	nssTempDirFlag = cflag.String(flagGroup, "nss-temp-db-dir", "",
		"Empty directory to create a temporary NSS DB in.  Only use "+
			"a directory that only this program can write to.  "+
			"(Required.)")
	rootPrefixFlag = cflag.String(flagGroup, "root-prefix",
		"Namecoin Restricted CKBI Root CA for ",
		"Prefix to apply to the Subject CommonName and NSS Nickname "+
			"of each generated root CA")
	intermediatePrefixFlag = cflag.String(flagGroup, "intermediate-prefix",
		"Namecoin Restricted CKBI Intermediate CA for ",
		"Prefix to apply to the Subject CommonName and NSS Nickname "+
			"of each generated intermediate CA")
	crossSignedPrefixFlag = cflag.String(flagGroup, "cross-signed-prefix",
		"Namecoin Restricted CKBI Cross-Signed CA for ",
		"Prefix to apply to the NSS Nickname of each generated "+
			"cross-signed CA")
	excludedDomainFlag = cflag.String(flagGroup, "excluded-domain",
		".bit", "Block each CKBI root CA from certifying for this "+
			"DNS domain name.")
)

var log, Log = xlog.New("ncdns.tlsrestrictnsssync")

const versionRegistryBase = registry.LOCAL_MACHINE
const versionRegistryName = "CurrentVersion"

const lastVersionRegistryBase = registry.LOCAL_MACHINE
const lastVersionRegistryName = "LastRestrictedNSSVersion"

// This is true when the registry key or value wasn't found, or if applying
// name constraints failed.  Such a symptom might indicate that the NSS
// application has been uninstalled, or is in the middle of an upgrade, but it
// could also indicate a misconfiguration that would prevent proper syncing.
var syncFailure = true
var syncFailureMux sync.Mutex

func checkFlagsSane() error {
	if versionRegistryKeyFlag.Value() == "" {
		return fmt.Errorf("Missing required config option tlsrestrictnss.regkey")
	}

	if nssCKBIDirFlag.Value() == "" {
		return fmt.Errorf("Missing required --tlsrestrictnss.nss-ckbi-dir " +
			"parameter")
	}

	if nssTempDirFlag.Value() == "" {
		return fmt.Errorf("Missing required --tlsrestrictnss.nss-temp-db-dir " +
			"parameter")
	}

	if nssDestDirFlag.Value() == "" {
		return fmt.Errorf("Missing required --tlsrestrictnss.nss-dest-db-dir " +
			"parameter")
	}

	if rootPrefixFlag.Value() == intermediatePrefixFlag.Value() ||
		rootPrefixFlag.Value() == crossSignedPrefixFlag.Value() ||
		intermediatePrefixFlag.Value() == crossSignedPrefixFlag.Value() {
		return fmt.Errorf("All 3 prefixes must be unique")
	}

	return nil
}

func watchVersionKey() error {
	lastSyncedVersion, err := getLastSyncedVersion()
	if err != nil {
		lastSyncedVersion = ""
	}

	for {
		// Check installed NSS version
		version, err := getInstalledVersion()
		if err != nil {
			log.Warne(err, "Couldn't detect installed NSS "+
				"version; disabling resolution as a precaution")

			syncFailureMux.Lock()
			syncFailure = true
			syncFailureMux.Unlock()

			time.Sleep(1 * time.Second)
			continue
		}

		// If we're already up to date, no problem
		if version == lastSyncedVersion {
			syncFailureMux.Lock()
			syncFailure = false
			syncFailureMux.Unlock()

			time.Sleep(1 * time.Second)
			continue
		}

		// Disable resolution while we're syncing
		syncFailureMux.Lock()
		syncFailure = true
		syncFailureMux.Unlock()

		// Wait for any ongoing installation to settle
		time.Sleep(10 * time.Second)

		// Apply restrictions
		log.Info("NSS has recently been upgraded from '" +
			lastSyncedVersion + "' to '" + version +
			"'; re-applying name constraints...")
		err = tlsrestrictnss.CalculateAndApplyConstraints(
			nssCKBIDirFlag.Value(), nssTempDirFlag.Value(),
			nssDestDirFlag.Value(), rootPrefixFlag.Value(),
			intermediatePrefixFlag.Value(),
			crossSignedPrefixFlag.Value(),
			excludedDomainFlag.Value(), false)
		if err != nil {
			log.Warne(err, "Couldn't apply name constraints; "+
				"disabling resolution as a precaution")

			syncFailureMux.Lock()
			syncFailure = true
			syncFailureMux.Unlock()

			time.Sleep(1 * time.Second)
			continue
		}
		log.Info("Successfully re-applied name constraints for NSS " +
			"version '" + version + "'.")

		// Remember the last synced version
		lastSyncedVersion = version
		err = setLastSyncedVersion(version)
		if err != nil {
			log.Warne(err, "Couldn't set last installed NSS "+
				"version")
		}

		time.Sleep(1 * time.Second)
	}

	return nil
}

func getInstalledVersion() (string, error) {
	// Open the version key
	versionKey, err := registry.OpenKey(versionRegistryBase,
		versionRegistryKeyFlag.Value(), registry.READ)
	if err != nil {
		return "", fmt.Errorf("Couldn't open version registry key: %s",
			err)
	}
	defer versionKey.Close()

	// Check version value
	version, _, err := versionKey.GetStringValue(versionRegistryName)
	if err != nil {
		return "", fmt.Errorf(
			"Couldn't get version registry string: %s", err)
	}

	return version, nil
}

func getLastSyncedVersion() (string, error) {
	// Open the ncdns key
	versionKey, err := registry.OpenKey(lastVersionRegistryBase,
		lastVersionRegistryKey, registry.READ)
	if err != nil {
		return "", fmt.Errorf("Couldn't open version registry key: %s",
			err)
	}
	defer versionKey.Close()

	// Check version value
	version, _, err := versionKey.GetStringValue(lastVersionRegistryName)
	if err != nil {
		return "", fmt.Errorf(
			"Couldn't get version registry string: %s", err)
	}

	return version, nil
}

func setLastSyncedVersion(version string) error {
	// Open the ncdns key
	versionKey, err := registry.OpenKey(lastVersionRegistryBase,
		lastVersionRegistryKey, registry.WRITE)
	if err != nil {
		return fmt.Errorf("Couldn't open version registry key: %s",
			err)
	}
	defer versionKey.Close()

	err = versionKey.SetStringValue(lastVersionRegistryName, version)
	if err != nil {
		return fmt.Errorf(
			"Couldn't set version registry value: %s", err)
	}

	return nil
}

// IsReady returns true if the name constraints are successfully synced.  If it
// returns false, it may be unsafe for TLS connections to rely on the synced
// name constraints.
func IsReady() bool {
	syncFailureMux.Lock()
	result := !syncFailure
	syncFailureMux.Unlock()

	return result
}

// Start starts a background thread that synchronizes the configured name
// constraints to the NSS database.
func Start() error {
	if syncEnableFlag.Value() {
		err := checkFlagsSane()
		if err != nil {
			return err
		}

		go watchVersionKey()
	} else {
		syncFailureMux.Lock()
		syncFailure = false
		syncFailureMux.Unlock()
	}
	return nil
}
