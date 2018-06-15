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

package main

import (
	"github.com/hlandau/xlog"
	"github.com/namecoin/tlsrestrictnss"
	"gopkg.in/hlandau/easyconfig.v1"
	"gopkg.in/hlandau/easyconfig.v1/cflag"
)

var (
	flagGroup      = cflag.NewGroup(nil, "tlsrestrict")
	nssDestDirFlag = cflag.String(flagGroup, "nss-dest-db-dir",
		"/etc/pki/nssdb", "Directory to write NSS certs to.")
	nssCKBIDirFlag = cflag.String(flagGroup, "nss-ckbi-dir", "/usr/lib64",
		"Directory containing "+tlsrestrictnss.NSSCKBIName)
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
	undoFlag = cflag.Bool(flagGroup, "undo", false,
		"Undo previously applied restrictions instead of applying "+
			"the restrictions")
)

var log, _ = xlog.New("tlsrestrict_nss_tool")
var config = easyconfig.Configurator{
	ProgramName: "tlsrestrict_nss_tool",
}

func init() {
	err := config.Parse(nil)
	if err != nil {
		log.Fatalf("Couldn't parse configuration: %s", err)
	}

	if nssTempDirFlag.Value() == "" {
		log.Fatal("Missing required --tlsrestrict.nss-temp-db-dir " +
			"parameter")
	}

	if rootPrefixFlag.Value() == intermediatePrefixFlag.Value() ||
		rootPrefixFlag.Value() == crossSignedPrefixFlag.Value() ||
		intermediatePrefixFlag.Value() == crossSignedPrefixFlag.Value() {
		log.Fatal("All 3 prefixes must be unique")
	}
}

func main() {
	log.Info("Extracting CKBI certificate list")
	CKBICerts, _, err := tlsrestrictnss.GetCKBICertList(
		nssCKBIDirFlag.Value(), nssTempDirFlag.Value(),
		rootPrefixFlag.Value(), intermediatePrefixFlag.Value(),
		crossSignedPrefixFlag.Value())
	log.Fatale(err, "Couldn't get CKBI certificate list")

	// TODO: look into not extracting DER encoding if undoFlag is enabled
	// (since it's not used in that case)
	log.Info("Extracting destination NSS certificate list")
	destCerts, _, err := tlsrestrictnss.GetCertList(nssDestDirFlag.Value(),
		rootPrefixFlag.Value(), intermediatePrefixFlag.Value(),
		crossSignedPrefixFlag.Value())
	log.Fatale(err, "Couldn't get destination certificate list")

	var nicksToRemove, nicksToAdd []string
	var opLabel string

	if undoFlag.Value() {
		opLabel = "undo"

		log.Info("Calculating certificates to undo")
		nicksToRemove, err =
			tlsrestrictnss.GetCertsWithCrossSignatures(destCerts,
				rootPrefixFlag.Value(),
				intermediatePrefixFlag.Value(),
				crossSignedPrefixFlag.Value())
		log.Fatale(err, "Couldn't calculate certificates to undo")
	} else {
		opLabel = "restriction"

		log.Info("Calculating certificates to remove")
		nicksToRemove, err = tlsrestrictnss.GetCertsToRemove(CKBICerts,
			destCerts, rootPrefixFlag.Value())
		log.Fatale(err, "Couldn't calculate certificates to remove")

		log.Info("Calculating certificates to add")
		nicksToAdd, err = tlsrestrictnss.GetCertsToAdd(CKBICerts, destCerts,
			rootPrefixFlag.Value())
		log.Fatale(err, "Couldn't calculate certificates to add")
	}

	log.Infof("Applying %s operation to NSS destination DB", opLabel)
	err = tlsrestrictnss.ApplyRestrictions(nssDestDirFlag.Value(),
		nssCKBIDirFlag.Value(), CKBICerts, nicksToRemove, nicksToAdd,
		rootPrefixFlag.Value(), intermediatePrefixFlag.Value(),
		crossSignedPrefixFlag.Value(), excludedDomainFlag.Value())
	log.Fatalef(err, "Couldn't apply %s operation", opLabel)
}
