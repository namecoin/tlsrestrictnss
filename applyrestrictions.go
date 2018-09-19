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
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/hlandau/xlog"
	"github.com/namecoin/crosssignnameconstraint"
)

// golint warning is a bug in xlog; bug report is at
// https://github.com/hlandau/xlog/issues/6
// nolint: golint
var log, Log = xlog.New("tlsrestrictnss")

// ApplyRestrictions applies the specified name constraint operations to the
// sqlite NSS database at the specified nssDestDir.  nssCKBIDir should contain
// a CKBI library (libnssckbi.so on GNU+Linux systems).  CKBICerts,
// nicksToRemove, and nicksToAdd are the output of GetCKBICertList(),
// GetCertsToRemove(), and GetCertsToAdd(), respectively.  rootPrefix,
// intermediatePrefix, and crossSignedPrefix are prepended to the nicknames of
// each certificate in CKBICerts when adding the root, intermediate, and
// cross-signed certificates.  rootPrefix and intermediatePrefix are also
// prepended to the Subject CommonName of each certificate in CKBICerts when
// generating the root and intermediate certificates.  excludedDomain specified
// the DNS domain name to exclude via a name constraint.
// TODO: Figure out how to avoid race conditions here.
func ApplyRestrictions(nssDestDir, nssCKBIDir string,
	CKBICerts map[string]NSSCertificate, nicksToRemove,
	nicksToAdd []string, rootPrefix, intermediatePrefix, crossSignedPrefix,
	excludedDomain string) error {
	// Delete any specified outdated certs
	err := applyDeleteOutdatedCerts(nssDestDir, nicksToRemove, rootPrefix,
		intermediatePrefix, crossSignedPrefix)
	if err != nil {
		return err
	}

	// Add any specified restricted certs
	err = applyAddRestrictedCerts(nssDestDir, nssCKBIDir, CKBICerts,
		nicksToAdd, rootPrefix, intermediatePrefix, crossSignedPrefix,
		excludedDomain)
	return err
}

func applyDeleteOutdatedCerts(nssDestDir string, nicksToRemove []string,
	rootPrefix, intermediatePrefix, crossSignedPrefix string) error {
	for _, nickname := range nicksToRemove {
		log.Infof("Deleting outdated root certificate for '%s'",
			nickname)

		err := deleteCertWithNickname(nssDestDir, rootPrefix+
			stripModuleFromNickname(nickname))
		if err != nil {
			return fmt.Errorf("Error deleting outdated root "+
				"certificate for '%s': %s", nickname, err)
		}

		log.Infof("Deleting outdated intermediate certificate for "+
			"'%s'", nickname)

		err = deleteCertWithNickname(nssDestDir, intermediatePrefix+
			stripModuleFromNickname(nickname))
		if err != nil {
			return fmt.Errorf("Error deleting outdated "+
				"intermediate certificate for '%s': %s",
				nickname, err)
		}

		log.Infof("Deleting outdated cross-signed certificate for "+
			"'%s'", nickname)

		err = deleteCertWithNickname(nssDestDir, crossSignedPrefix+
			stripModuleFromNickname(nickname))
		if err != nil {
			return fmt.Errorf("Error deleting outdated "+
				"cross-signed certificate for '%s': %s",
				nickname, err)
		}

		log.Infof("Deleting outdated original certificate for "+
			"'%s'", nickname)

		err = deleteCertWithNickname(nssDestDir, nickname)
		if err != nil {
			return fmt.Errorf("Error deleting outdated original "+
				"certificate for '%s': %s", nickname, err)
		}
	}

	return nil
}

func applyAddRestrictedCerts(nssDestDir, nssCKBIDir string,
	CKBICerts map[string]NSSCertificate, nicksToAdd []string, rootPrefix,
	intermediatePrefix, crossSignedPrefix,
	excludedDomain string) (err error) {
	// Give certutil access to built-in certs (for purpose of untrusting
	// original certs)
	err = enableCKBIVisibility(nssCKBIDir, nssDestDir)
	if err != nil {
		return fmt.Errorf("Error enabling CKBI visibility: %s", err)
	}
	defer func() {
		if cerr := disableCKBIVisibility(nssDestDir); cerr != nil && err == nil {
			err = fmt.Errorf("Error disabling CKBI visibility: %s", cerr)
		}
	}()

	for _, nickname := range nicksToAdd {
		log.Infof("Generating cross-signature for '%s'", nickname)

		rootDER, intermediateDER, crossSignedDER, err :=
			crosssignnameconstraint.GetCrossSignedDER(rootPrefix,
				intermediatePrefix, excludedDomain,
				CKBICerts[nickname].DER)
		if err != nil {
			return fmt.Errorf("Error processing certificate with "+
				"nickname '%s': %s", nickname, err)
		}

		log.Infof("Distrusting unrestricted CA for '%s'", nickname)

		err = distrustCertWithNickname(nssDestDir, nickname)
		if err != nil {
			return fmt.Errorf("Error distrusting unrestricted "+
				"CA for '%s': %s", nickname, err)
		}

		log.Infof("Importing root CA for '%s'", nickname)

		err = addCert(nssDestDir, rootPrefix+
			stripModuleFromNickname(nickname),
			CKBICerts[nickname].TLSTrust+","+
				CKBICerts[nickname].SMIMETrust+","+
				CKBICerts[nickname].JARXPITrust, rootDER)
		if err != nil {
			return fmt.Errorf("Error importing root CA for "+
				"'%s': %s", nickname, err)
		}

		log.Infof("Importing intermediate CA for '%s'", nickname)

		err = addCert(nssDestDir, intermediatePrefix+
			stripModuleFromNickname(nickname), ",,",
			intermediateDER)
		if err != nil {
			return fmt.Errorf("Error importing intermediate CA "+
				"for '%s': %s", nickname, err)
		}

		log.Infof("Importing cross-signed CA for '%s'", nickname)

		err = addCert(nssDestDir, crossSignedPrefix+
			stripModuleFromNickname(nickname), ",,",
			crossSignedDER)
		if err != nil {
			return fmt.Errorf("Error importing cross-signed CA "+
				"for '%s': %s", nickname, err)
		}
	}

	return nil
}

func stripModuleFromNickname(nickname string) string {
	if strings.Contains(nickname, ":") {
		return strings.SplitN(nickname, ":", 2)[1]
	}

	return nickname
}

func deleteCertWithNickname(nssDestDir, nickname string) (err error) {
	// Write an NSS batch file to delete the cert from NSS
	// Batch files are needed in order to handle Unicode nicknames
	// on Windows.
	batchPath := nssDestDir + "/" + "tlsrestrict_nss_batch.txt"
	err = ioutil.WriteFile(batchPath, []byte("-D -n \""+nickname+"\"\n"), 0600)
	if err != nil {
		return fmt.Errorf("Error writing certutil batch file: %s", err)
	}
	defer func() {
		if cerr := os.Remove(batchPath); cerr != nil && err == nil {
			err = fmt.Errorf("Error removing certutil batch file: %s", cerr)
		}
	}()

	// Execute the NSS batch file with certutil.
	// AFAICT the "Subprocess launching with variable" warning from gas is
	// a false alarm here.
	// nolint: gas
	cmd := exec.Command(NSSCertutilName, "-d", "sql:"+
		nssDestDir, "-B", "-i", batchPath)

	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		// If the specified certificate is already not present in the
		// NSS database, then we can safely ignore the error.
		// Unfortunately, different NSS versions return a different
		// error code for this case.  Older NSS versions (e.g. the
		// version in Fedora 26) return SEC_ERROR_UNRECOGNIZED_OID,
		// while newer NSS versions (e.g. the version in Fedora 28)
		// return SEC_ERROR_INVALID_ARGS.  So we need to check for
		// both.
		if strings.Contains(string(stdoutStderr), "SEC_ERROR_UNRECOGNIZED_OID") ||
			strings.Contains(string(stdoutStderr), "SEC_ERROR_INVALID_ARGS") {
			log.Warn("Tried to delete certificate from NSS " +
				"database, but the certificate was already " +
				"not present in NSS database")
		} else if strings.Contains(string(stdoutStderr),
			"SEC_ERROR_PKCS11_GENERAL_ERROR") {
			log.Warn("Temporary SEC_ERROR_PKCS11_GENERAL_ERROR " +
				"deleting certificate from NSS database; " +
				"retrying in 1ms...")
			time.Sleep(1 * time.Millisecond)
			return deleteCertWithNickname(nssDestDir, nickname)
		} else {
			return fmt.Errorf(
				"Error deleting certificate from NSS "+
					"database: %s\n%s", err, stdoutStderr)
		}
	}

	return nil
}

func distrustCertWithNickname(nssDestDir, nickname string) (err error) {
	// Write an NSS batch file to distrust the cert in NSS
	// Batch files are needed in order to handle Unicode nicknames
	// on Windows.
	batchPath := nssDestDir + "/" + "tlsrestrict_nss_batch.txt"
	err = ioutil.WriteFile(batchPath,
		[]byte("-M -n \""+nickname+"\" -t ,,\n"), 0600)
	if err != nil {
		return fmt.Errorf("Error writing certutil batch file: %s", err)
	}
	defer func() {
		if cerr := os.Remove(batchPath); cerr != nil && err == nil {
			err = fmt.Errorf("Error removing certutil batch file: %s", cerr)
		}
	}()

	// Execute the NSS batch file with certutil.
	// AFAICT the "Subprocess launching with variable" warning from gas is
	// a false alarm here.
	// nolint: gas
	cmd := exec.Command(NSSCertutilName, "-d", "sql:"+
		nssDestDir, "-B", "-i", batchPath)

	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(stdoutStderr), "SEC_ERROR_PKCS11_GENERAL_ERROR") {
			log.Warn("Temporary SEC_ERROR_PKCS11_GENERAL_ERROR " +
				"distrusting certificate in NSS database; " +
				"retrying in 1ms...")
			time.Sleep(1 * time.Millisecond)
			return distrustCertWithNickname(nssDestDir, nickname)
		}

		return fmt.Errorf(
			"Error distrusting certificate in NSS database: "+
				"%s\n%s", err, stdoutStderr)
	}

	return nil
}

func addCert(nssDestDir, nickname, trust string, DER []byte) (err error) {
	// Convert DER to PEM
	PEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: DER})
	if PEM == nil {
		return fmt.Errorf("Error encoding DER certificate to PEM")
	}

	// Write an NSS batch file to add the cert to NSS.
	// Batch files are needed in order to handle Unicode nicknames
	// on Windows.
	batchPath := nssDestDir + "/" + "tlsrestrict_nss_batch.txt"
	err = ioutil.WriteFile(batchPath,
		[]byte("-A -t "+trust+" -n \""+nickname+"\" -a\n"), 0600)
	if err != nil {
		return fmt.Errorf("Error writing certutil batch file: %s", err)
	}
	defer func() {
		if cerr := os.Remove(batchPath); cerr != nil && err == nil {
			err = fmt.Errorf("Error removing certutil batch file: %s", cerr)
		}
	}()

	// Execute the NSS batch file with certutil.
	// AFAICT the "Subprocess launching with variable" warning from gas is
	// a false alarm here.
	// nolint: gas
	cmd := exec.Command(NSSCertutilName, "-d", "sql:"+
		nssDestDir, "-B", "-i", batchPath)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("Error getting standard input pipe for certutil: %s", err)
	}

	c := make(chan error)

	go func() {
		_, cerr := stdin.Write(PEM)
		if cerr != nil {
			c <- fmt.Errorf("Error writing to standard input pipe "+
				"for certutil: %s", cerr)
			return
		}

		cerr = stdin.Close()
		if cerr != nil {
			c <- fmt.Errorf("Error closing standard input pipe for certutil: %s", cerr)
			return
		}

		c <- nil
	}()

	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(stdoutStderr), "SEC_ERROR_PKCS11_GENERAL_ERROR") {
			log.Warn("Temporary SEC_ERROR_PKCS11_GENERAL_ERROR " +
				"injecting certificate to NSS database; " +
				"retrying in 1ms...")
			time.Sleep(1 * time.Millisecond)
			return addCert(nssDestDir, nickname, trust, DER)
		}

		return fmt.Errorf(
			"Error injecting certificate to NSS database: %s\n%s",
			err, stdoutStderr)
	}
	err = <-c
	return err
}
