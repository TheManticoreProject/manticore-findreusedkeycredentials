package main

import (
	"os"
	"strings"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt"
	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/Manticore/windows/keycredentiallink"

	"fmt"

	"github.com/TheManticoreProject/goopts/parser"
)

var (
	// Configuration
	useLdaps bool
	debug    bool

	// Network settings
	domainController string
	ldapPort         int

	// Authentication details
	authDomain   string
	authUsername string
	authPassword string
	authHashes   string

	exportFolder string
	exportKeys   bool
	useKerberos  bool
)

func parseArgs() {
	ap := parser.ArgumentsParser{Banner: "FindReusedKeyCredentials - by Remi GASCOU (Podalirius) @ TheManticoreProject - v1.0.0"}

	// Configuration flags
	ap.NewBoolArgument(&debug, "", "--debug", false, "Debug mode.")

	group_exportSettings, err := ap.NewArgumentGroup("Export Settings")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		group_exportSettings.NewStringArgument(&exportFolder, "-ed", "--export-dir", "./keys/", false, "Export the RSA keys to this folder.")
		group_exportSettings.NewBoolArgument(&exportKeys, "-ek", "--export-keys", false, "Export the found RSA keys.")
	}

	group_ldapSettings, err := ap.NewArgumentGroup("LDAP Connection Settings")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		group_ldapSettings.NewStringArgument(&domainController, "-dc", "--dc-ip", "", true, "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted, it will use the domain part (FQDN) specified in the identity parameter.")
		group_ldapSettings.NewTcpPortArgument(&ldapPort, "-lp", "--ldap-port", 389, false, "Port number to connect to LDAP server.")
		group_ldapSettings.NewBoolArgument(&useLdaps, "-L", "--use-ldaps", false, "Use LDAPS instead of LDAP.")
		group_ldapSettings.NewBoolArgument(&useKerberos, "-k", "--use-kerberos", false, "Use Kerberos instead of NTLM.")
	}

	group_auth, err := ap.NewArgumentGroup("Authentication")
	if err != nil {
		fmt.Printf("[error] Error creating ArgumentGroup: %s\n", err)
	} else {
		group_auth.NewStringArgument(&authDomain, "-d", "--domain", "", true, "Active Directory domain to authenticate to.")
		group_auth.NewStringArgument(&authUsername, "-u", "--username", "", true, "User to authenticate as.")
		group_auth.NewStringArgument(&authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		group_auth.NewStringArgument(&authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
	}

	ap.Parse()

	if useLdaps && !group_ldapSettings.LongNameToArgument["--port"].IsPresent() {
		ldapPort = 636
	}

	if !strings.HasSuffix(exportFolder, "/") {
		exportFolder += "/"
	}
}

func main() {
	parseArgs()

	creds, err := credentials.NewCredentials(authDomain, authUsername, authPassword, authHashes)
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating credentials: %s", err))
		return
	}

	if debug {
		if !useLdaps {
			logger.Debug(fmt.Sprintf("Connecting to remote ldap://%s:%d ...", domainController, ldapPort))
		} else {
			logger.Debug(fmt.Sprintf("Connecting to remote ldaps://%s:%d ...", domainController, ldapPort))
		}
	}

	ldapSession, err := ldap.NewSession(
		domainController,
		ldapPort,
		creds,
		useLdaps,
		useKerberos,
	)
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating LDAP session: %s", err))
		return
	}

	connected, err := ldapSession.Connect()
	if err != nil {
		logger.Warn(fmt.Sprintf("Error connecting to LDAP: %s", err))
		return
	}
	defer ldapSession.Close()

	if connected {
		logger.Info(fmt.Sprintf("Connected as '%s\\%s'", authDomain, authUsername))

		query := "(msDS-KeyCredentialLink=*)"
		if debug {
			logger.Debug(fmt.Sprintf("LDAP query used: %s", query))
		}

		attributes := []string{"distinguishedName", "msDS-KeyCredentialLink"}
		ldapResults, err := ldapSession.QueryWholeSubtree("", query, attributes)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error querying LDAP: %s", err))
			return
		}

		if debug {
			logger.Debug(fmt.Sprintf("LDAP results: %d", len(ldapResults)))
		}

		keysToExport := map[string]bcrypt.KeyMaterial{}
		foundKeys := map[string][]string{}
		for _, entry := range ldapResults {
			if debug {
				logger.Debug(fmt.Sprintf("Entry: %s", entry.GetAttributeValue("distinguishedName")))
			}
			for _, value := range entry.GetEqualFoldRawAttributeValues("msDS-KeyCredentialLink") {
				dnWithBinary := ldap.DNWithBinary{}
				_, err := dnWithBinary.Unmarshal(value)
				if err != nil {
					logger.Warn(fmt.Sprintf("Error unmarshalling DN with binary: %s", err))
					continue
				}

				kc := keycredentiallink.KeyCredentialLink{}
				kc.ParseDNWithBinary(dnWithBinary)

				keyFingerprint := kc.KeyMaterial.(*keys.BCRYPT_RSA_PUBLIC_KEY).Fingerprint()

				if len(foundKeys[keyFingerprint]) == 1 {
					keysToExport[keyFingerprint] = kc.KeyMaterial
				}
				foundKeys[keyFingerprint] = append(foundKeys[keyFingerprint], entry.GetAttributeValue("distinguishedName"))
			}
		}

		keyId := 0
		for keyFingerprint, dNs := range foundKeys {
			if len(dNs) > 1 {
				keyId++
				if exportKeys {
					keyExportPath := fmt.Sprintf("%s%04d.pem", exportFolder, keyId)
					pemData, err := keysToExport[keyFingerprint].(*keys.BCRYPT_RSA_PUBLIC_KEY).ExportPEM()
					if err != nil {
						logger.Warn(fmt.Sprintf("Error exporting key to PEM: %s", err))
					} else {
						err = os.WriteFile(keyExportPath, pemData, 0644)
						if err != nil {
							logger.Warn(fmt.Sprintf("Error writing key to file: %s", err))
						}
					}
					logger.Info(fmt.Sprintf("These %d objects share the same key (%s):", len(dNs), keyExportPath))
				} else {
					logger.Info(fmt.Sprintf("These %d objects share the same key:", len(dNs)))
				}

				logger.Info(fmt.Sprintf("Key fingerprint: %s", keyFingerprint))
				for k, dn := range dNs {
					if k != len(dNs)-1 {
						logger.Info(fmt.Sprintf("├── %s", dn))
					} else {
						logger.Info(fmt.Sprintf("└── %s", dn))
					}
				}
			}
		}

	} else {
		if debug {
			logger.Warn("Error: Could not create ldapSession.")
		}
	}

	logger.Info("All done.")
}
