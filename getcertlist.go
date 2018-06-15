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
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// NSSCertificate represents a certificate from an NSS trust store.  See the
// certutil documentation for the flags that exist in TLSTrust, SMIMETrust, and
// JARXPITrust.
type NSSCertificate struct {
	TLSTrust    string
	SMIMETrust  string
	JARXPITrust string
	DER         []byte
}

func parseCertList(nssDir, allCertsText string) (map[string]NSSCertificate,
	string, error) {
	// One string per cert
	certLines := strings.Split(allCertsText, "\n")

	certs := make(map[string]NSSCertificate)

	for _, certLine := range certLines {
		// Filter out whitespace padding at start/end
		certLineTrimmed := strings.TrimSpace(certLine)

		// Filter out the header
		if len(certLineTrimmed) == 0 {
			continue
		}
		if strings.HasSuffix(certLineTrimmed, "Trust Attributes") {
			continue
		}
		if strings.HasSuffix(certLineTrimmed, "SSL,S/MIME,JAR/XPI") {
			continue
		}

		// Get the trust bits (e.g. "CP,C,") into their own string
		certLineSplit := strings.Split(certLineTrimmed, " ")
		certLineTrust := certLineSplit[len(certLineSplit)-1]

		// Separate the trust bits by usage (e.g. "CP")
		certLineTrustSplit := strings.Split(certLineTrust, ",")
		if len(certLineTrustSplit) != 3 {
			return nil, "", fmt.Errorf("Trust attributes should have 3 usages")
		}
		certTLSTrust := certLineTrustSplit[0]
		certSMIMETrust := certLineTrustSplit[1]
		certJARXPITrust := certLineTrustSplit[2]

		certNickname := strings.TrimSpace(strings.TrimSuffix(
			certLineTrimmed, certLineTrust))

		log.Infof("Extracting DER certificate for %s", certNickname)

		// Dump the cert's DER value
		// AFAICT the "Subprocess launching with variable" warning from
		// gas is a false alarm here.
		// nolint: gas
		cmdDumpCert := exec.Command(NSSCertutilName,
			"-d", "sql:"+nssDir, "-L", "-n", certNickname, "-r")
		certDER, err := cmdDumpCert.Output()
		if err != nil {
			exiterr, ok := err.(*exec.ExitError)
			if ok {
				return nil, "", fmt.Errorf("Error dumping "+
					"cert '%s': certutil returned a "+
					"nonzero exit code: %s\n%s\n%s",
					certNickname, err, certDER,
					string(exiterr.Stderr))
			}
			return nil, "", fmt.Errorf("Error dumping cert '%s': %s", certNickname, err)
		}

		certs[certNickname] = NSSCertificate{
			TLSTrust:    certTLSTrust,
			SMIMETrust:  certSMIMETrust,
			JARXPITrust: certJARXPITrust,
			DER:         certDER,
		}
	}

	return certs, allCertsText, nil
}

// GetOldCKBICertList gets a previously extracted list of CKBI certificates
// from the file "old_ckbi_list.txt" in the specified directory.  (This
// function is unused legacy code and may be removed at any time.)
func GetOldCKBICertList(nssDir string) (map[string]NSSCertificate, string,
	error) {
	allCertsText, err := ioutil.ReadFile(nssDir + "/old_ckbi_list.txt")
	if err != nil {
		return nil, "", fmt.Errorf("Error listing old certs: %s", err)
	}

	return parseCertList(nssDir, string(allCertsText))
}

// GetCertList extracts the certificates from the NSS sqlite database in
// nssDir.
func GetCertList(nssDir string) (map[string]NSSCertificate, string, error) {
	// Get a list of all certs
	// AFAICT the "Subprocess launching with variable" warning from gas is
	// a false alarm here.
	// nolint: gas
	cmdListCerts := exec.Command(NSSCertutilName,
		"-d", "sql:"+nssDir, "-L", "-h", "all")
	allCertsText, err := cmdListCerts.Output()
	if err != nil {
		exiterr, ok := err.(*exec.ExitError)
		if ok {
			// https://stackoverflow.com/questions/10385551/get-exit-code-go
			// This works on both Unix and Windows. Although package
			// syscall is generally platform dependent, WaitStatus is
			// defined for both Unix and Windows and in both cases has
			// an ExitStatus() method with the same signature.
			if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				// For some unknown reason, certutil returns
				// exit code 1 on Fedora even on success here.
				if status.ExitStatus() != 1 {
					return nil, "", fmt.Errorf(
						"Error listing certs: "+
							"certutil returned "+
							"exit code %d\n%s\n%s",
						status.ExitStatus(),
						allCertsText,
						string(exiterr.Stderr))
				}
			} else {
				return nil, "", fmt.Errorf(
					"Error listing certs: certutil "+
						"returned a nonzero exit "+
						"code: %s\n%s\n%s", err,
					allCertsText,
					string(exiterr.Stderr))
			}
		} else {
			return nil, "", fmt.Errorf("Error listing certs: %s", err)
		}
	}

	return parseCertList(nssDir, string(allCertsText))
}

// GetCKBICertList extracts the certificates from a Mozilla CKBI (built-in
// certificates) module.  nssCKBIDir should contain a Mozilla CKBI module
// (usually libnssckbi.so); nssTempDir should be an empty directory that only
// trusted applications can read or write to.
func GetCKBICertList(nssCKBIDir, nssTempDir string) (
	certs map[string]NSSCertificate, rawCerts string, err error) {
	// Create empty temporary NSS database
	err = createTempDB(nssTempDir)
	if err != nil {
		return nil, "", fmt.Errorf("Error creating temporary NSS database: %s",
			err)
	}
	defer func() {
		if cerr := deleteTempDB(nssTempDir); cerr != nil && err == nil {
			err = cerr
		}
	}()

	// Give certutil access to built-in certs
	err = enableCKBIVisibility(nssCKBIDir, nssTempDir)
	if err != nil {
		return nil, "", fmt.Errorf("Error enabling CKBI visibility: %s", err)
	}

	return GetCertList(nssTempDir)
}

func enableCKBIVisibility(nssCKBIDir, nssDir string) error {
	CKBILibrary, err := ioutil.ReadFile(nssCKBIDir + "/" + NSSCKBIName)
	if err != nil {
		return fmt.Errorf("Error reading CKBI: %s", err)
	}

	err = ioutil.WriteFile(nssDir+"/"+NSSCKBIName, CKBILibrary, 0600)
	if err != nil {
		return fmt.Errorf("Error writing CKBI: %s", err)
	}

	return nil
}

func disableCKBIVisibility(nssDir string) error {
	err := os.Remove(nssDir + "/" + NSSCKBIName)
	if err != nil {
		return fmt.Errorf("Error removing CKBI: %s", err)
	}

	return nil
}

// GetCertsWithCrossSignatures returns the nicknames of all certs for which any
// cross-signature-related certificates are present in destCerts.
func GetCertsWithCrossSignatures(destCerts map[string]NSSCertificate,
	rootPrefix, intermediatePrefix, crossSignedPrefix string) ([]string,
	error) {
	var result []string

	for nickname := range destCerts {
		// Be aggressive at detection in this function, because it's
		// used to repair broken installations
		_, destNamecoinRootPresent := destCerts[rootPrefix+
			strings.TrimPrefix(nickname, rootPrefix)]
		_, destNamecoinIntermediatePresent :=
			destCerts[intermediatePrefix+strings.TrimPrefix(
				nickname, intermediatePrefix)]
		_, destNamecoinCrossSignedPresent :=
			destCerts[crossSignedPrefix+strings.TrimPrefix(
				nickname, crossSignedPrefix)]

		// Skip if this cert doesn't have a Namecoin
		// root/intermediate/cross-signed version already
		if !destNamecoinRootPresent &&
			!destNamecoinIntermediatePresent &&
			!destNamecoinCrossSignedPresent {
			continue
		}

		// At this point, we know it's a TLS root CA (originally from
		// CKBI) that we previously cross-signed
		result = append(result, nickname)
		continue
	}

	return result, nil
}

// Returns bool indicating if the certs have different trust, and a string
// indicating a message the first attribute that changed.
func trustAtributesChanged(cert1, cert2 NSSCertificate) (bool, string) {
	if cert1.TLSTrust != cert2.TLSTrust {
		return true, "TLS"
	}

	if cert1.SMIMETrust != cert2.SMIMETrust {
		return true, "S/MIME"
	}

	if cert1.JARXPITrust != cert2.JARXPITrust {
		return true, "JAR/XPI"
	}

	return false, ""
}

// TODO: use PEM encoding for this instead, so that we don't have to worry
// about boundary detection
func derValueChanged(cert1, cert2 NSSCertificate) bool {
	// When 2 certificates with the same Subject exist in the
	// destination DB, we actually end up with a concatenation of
	// both DER values.  So we have to do a prefix match and a
	// suffix match rather than an exact match.
	if len(cert2.DER) < len(cert1.DER) ||
		(len(cert2.DER) >= len(cert1.DER) &&
			!bytes.Equal(cert1.DER, cert2.DER[0:len(cert1.DER)]) &&
			!bytes.Equal(cert1.DER,
				cert2.DER[len(cert2.DER)-len(cert1.DER):len(cert2.DER)])) {
		return true
	}
	return false
}

func shouldTLSRootCABeRemoved(nickname string,
	CKBICertsNoModule map[string]NSSCertificate, destCert,
	destNamecoinRoot NSSCertificate) bool {
	CKBICert, CKBICertPresent := CKBICertsNoModule[nickname]
	if !CKBICertPresent {
		log.Infof("No longer in CKBI, will be removed: %s", nickname)
		return true
	}

	if changed, message := trustAtributesChanged(CKBICert,
		destNamecoinRoot); changed {
		log.Infof("%s trust has changed, will be replaced: %s", message, nickname)
		return true
	}

	if derValueChanged(CKBICert, destCert) {
		log.Infof("DER value has changed (len CKBI %d, dest %d), "+
			"will be replaced: %s", len(CKBICert.DER),
			len(destCert.DER), nickname)
		return true
	}

	return false
}

// GetCertsToRemove returns the nicknames of all certs that should be removed
// from the NSS database prior to adding fresh cross-signatures.
func GetCertsToRemove(CKBICerts, destCerts map[string]NSSCertificate,
	rootPrefix string) ([]string, error) {
	var result []string

	CKBICertsNoModule := make(map[string]NSSCertificate)
	for nickname, CKBICert := range CKBICerts {
		CKBICertsNoModule[stripModuleFromNickname(nickname)] = CKBICert
	}

	for nickname, destCert := range destCerts {
		destNamecoinRoot, destNamecoinRootPresent := destCerts[rootPrefix+nickname]

		// Skip if this cert doesn't have a Namecoin root version already
		if !destNamecoinRootPresent {
			continue
		}

		// At this point, we know it's a TLS root CA (originally from
		// CKBI) that we previously cross-signed

		if shouldTLSRootCABeRemoved(nickname, CKBICertsNoModule,
			destCert, destNamecoinRoot) {
			result = append(result, nickname)
			continue
		}
	}

	return result, nil
}

func shouldTLSRootCABeAdded(nickname string, CKBICert NSSCertificate,
	destCerts map[string]NSSCertificate, rootPrefix string) bool {
	destCert, destCertPresent := destCerts[stripModuleFromNickname(nickname)]

	destNamecoinRoot, destNamecoinRootPresent := destCerts[rootPrefix+
		stripModuleFromNickname(nickname)]

	if !destCertPresent && !destNamecoinRootPresent {
		// We haven't previously cross-signed this root CA,
		// and the user hasn't modified this root CA.
		// Cross-sign it.
		log.Infof("Cert not present in destination DB, will be "+
			"cross-signed: %s", nickname)
		return true
	}

	if destCertPresent && !destNamecoinRootPresent {
		// We haven't previously cross-signed this root CA,
		// and the user has already made their own trust modifications.

		// The user has modified this root CA from the CKBI.  Don't cross-sign it.
		return false
	}

	if destCertPresent && destNamecoinRootPresent {
		// We previously cross-signed this root CA.
		// We need to check whether it's changed in CKBI since last time.

		if changed, message := trustAtributesChanged(CKBICert,
			destNamecoinRoot); changed {
			log.Infof("%s trust has changed, will be replaced: %s", message, nickname)
			return true
		}

		if derValueChanged(CKBICert, destCert) {
			log.Infof("DER value has changed (len CKBI %d, "+
				"dest %d), will be replaced: %s",
				len(CKBICert.DER), len(destCert.DER), nickname)
			return true
		}

		// Cert hasn't changed since last time; leave it alone.
	}

	return false
}

// GetCertsToAdd returns the nicknames of all certs for which cross-signatures
// should be added to the NSS database.
func GetCertsToAdd(CKBICerts, destCerts map[string]NSSCertificate,
	rootPrefix string) ([]string, error) {
	var result []string

	for nickname, CKBICert := range CKBICerts {
		// Skip if not a TLS trust anchor
		if !strings.Contains(CKBICert.TLSTrust, "C") {
			continue
		}

		// At this point, we know that it's a TLS root CA in CKBI

		if shouldTLSRootCABeAdded(nickname, CKBICert, destCerts, rootPrefix) {
			result = append(result, nickname)
			continue
		}
	}

	return result, nil
}

func createTempDB(nssTempDir string) error {
	// Create database
	// AFAICT the "Subprocess launching with variable" warning from gas is
	// a false alarm here.
	// nolint: gas
	cmdCreateDB := exec.Command(NSSCertutilName,
		"-d", "sql:"+nssTempDir, "-N", "--empty-password")
	stdoutStderrCreateDB, err := cmdCreateDB.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Error creating temporary NSS database: "+
			"%s\n%s", err, stdoutStderrCreateDB)
	}

	return nil
}

func deleteTempDB(nssTempDir string) error {
	// Delete cert9.db
	err := os.Remove(nssTempDir + "/" + "cert9.db")
	if err != nil {
		return fmt.Errorf("Error deleting cert9.db from temporary NSS "+
			"database directory: %s", err)
	}

	// Delete key4.db
	err = os.Remove(nssTempDir + "/" + "key4.db")
	if err != nil {
		return fmt.Errorf("Error deleting key4.db from temporary NSS "+
			"database directory: %s", err)
	}

	// Delete pkcs11.txt
	err = os.Remove(nssTempDir + "/" + "pkcs11.txt")
	if err != nil {
		return fmt.Errorf("Error deleting pkcs11.txt from temporary NSS "+
			"database directory: %s", err)
	}

	// Delete CKBI
	err = disableCKBIVisibility(nssTempDir)
	if err != nil {
		return fmt.Errorf("Error disabling CKBI visibility from temporary NSS "+
			"database directory: %s", err)
	}

	return nil
}
