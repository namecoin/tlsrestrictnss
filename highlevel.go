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

package tlsrestrictnss

import (
	"fmt"
)

// CalculateAndApplyConstraints is a high-level wrapper for the other functions
// in tlsrestrictnss.  It extracts the certificate lists from CKBI and the NSS
// DB, calculates which changes to make, and applies those changes.
// A previous operation can be reversed by setting undo to true.
func CalculateAndApplyConstraints(nssCKBIDir, nssTempDir, nssDestDir,
	rootPrefix, intermediatePrefix, crossSignedPrefix,
	excludedDomain string, undo bool) error {
	log.Info("Extracting CKBI certificate list")
	CKBICerts, _, err := GetCKBICertList(nssCKBIDir, nssTempDir,
		rootPrefix, intermediatePrefix, crossSignedPrefix)
	if err != nil {
		return fmt.Errorf("Couldn't get CKBI certificate list: %s", err)
	}

	// TODO: look into not extracting DER encoding if undo is enabled
	// (since it's not used in that case)
	log.Info("Extracting destination NSS certificate list")
	destCerts, _, err := GetCertList(nssDestDir,
		rootPrefix, intermediatePrefix, crossSignedPrefix)
	if err != nil {
		return fmt.Errorf("Couldn't get destination certificate list: %s", err)
	}

	var nicksToRemove, nicksToAdd []string
	var opLabel string

	if undo {
		opLabel = "undo"

		log.Info("Calculating certificates to undo")
		nicksToRemove, err =
			GetCertsWithCrossSignatures(destCerts,
				rootPrefix, intermediatePrefix,
				crossSignedPrefix)
		if err != nil {
			return fmt.Errorf("Couldn't calculate certificates to undo: %s", err)
		}
	} else {
		opLabel = "restriction"

		log.Info("Calculating certificates to remove")
		nicksToRemove, err = GetCertsToRemove(CKBICerts, destCerts,
			rootPrefix)
		if err != nil {
			return fmt.Errorf("Couldn't calculate certificates to remove: %s", err)
		}

		log.Info("Calculating certificates to add")
		nicksToAdd, err = GetCertsToAdd(CKBICerts, destCerts,
			rootPrefix)
		if err != nil {
			return fmt.Errorf("Couldn't calculate certificates to add: %s", err)
		}
	}

	log.Infof("Applying %s operation to NSS destination DB", opLabel)
	err = ApplyRestrictions(nssDestDir,
		nssCKBIDir, CKBICerts, nicksToRemove, nicksToAdd,
		rootPrefix, intermediatePrefix, crossSignedPrefix,
		excludedDomain)
	if err != nil {
		return fmt.Errorf("Couldn't apply %s operation: %s", opLabel, err)
	}

	return nil
}
