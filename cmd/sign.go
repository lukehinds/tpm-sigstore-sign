/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"

	"crypto"
	"reflect"

	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	tpm_conn "github.com/lukehinds/tpm-sigstore-sign/pkg/tpm"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const ()

var (
	encryptionCertNVIndex = 0x01c00002
	handleNames = map[string][]tpm2.HandleType{
		"all":       {tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    {tpm2.HandleTypeLoadedSession},
		"saved":     {tpm2.HandleTypeSavedSession},
		"transient": {tpm2.HandleTypeTransient},
	}

	defaultEKTemplate = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagAdminWithPolicy | tpm2.FlagRestricted | tpm2.FlagDecrypt,
		AuthPolicy: []byte{
			0x83, 0x71, 0x97, 0x67, 0x44, 0x84,
			0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D,
			0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52,
			0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
			0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
			0x69, 0xAA,
		},
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:    2048,
			ModulusRaw: make([]byte, 256),
		},
	}

	// https://github.com/google/go-tpm/blob/master/tpm2/constants.go#L152
	defaultKeyParams = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagSign | tpm2.FlagRestricted | tpm2.FlagFixedTPM |
			tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth,
		AuthPolicy: []byte{},
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	}

	unrestrictedKeyParams = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagSign,
		AuthPolicy: []byte{},
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	}
)

func readEKCert(path string, certIdx, tmplIdx uint32) ([]byte, error) {
	rwc, err := tpm2.OpenTPM(path)
	if err != nil {
		return nil, fmt.Errorf("can't open TPM at %q: %v", path, err)
	}
	defer rwc.Close()
	ekCert, err := tpm2.NVRead(rwc, tpmutil.Handle(certIdx))
	if err != nil {
		return nil, fmt.Errorf("reading EK cert: %v", err)
	}
	// Sanity-check that this is a valid certificate.
	cert, err := x509.ParseCertificate(ekCert)
	if err != nil {
		return nil, fmt.Errorf("parsing EK cert: %v", err)
	}

	// Initialize EK and compare public key to ekCert.PublicKey.
	var ekh tpmutil.Handle
	var ekPub crypto.PublicKey
	if tmplIdx != 0 {
		ekTemplate, err := tpm2.NVRead(rwc, tpmutil.Handle(tmplIdx))
		if err != nil {
			return nil, fmt.Errorf("reading EK template: %v", err)
		}
		ekh, ekPub, err = tpm2.CreatePrimaryRawTemplate(rwc, tpm2.HandleEndorsement, tpm2.PCRSelection{}, "", "", ekTemplate)
		if err != nil {
			return nil, fmt.Errorf("creating EK: %v", err)
		}
	} else {
		ekh, ekPub, err = tpm2.CreatePrimary(rwc, tpm2.HandleEndorsement, tpm2.PCRSelection{}, "", "", defaultEKTemplate)
		if err != nil {
			return nil, fmt.Errorf("creating EK: %v", err)
		}
	}
	defer tpm2.FlushContext(rwc, ekh)
	
	// convert cert to PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ekCert,
	})

	// write to file
	certPEMFile, err := os.Create("certPEMFile.pem")
	if err != nil {
		return nil, fmt.Errorf("creating ekcert.pem: %v", err)
	}
	defer certPEMFile.Close()
	certPEMFile.Write(certPEM)
	

	// convert public key to PEM format
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(ekPub.(*rsa.PublicKey)),
	})

	// write to file
	pubPemFile, err := os.Create("pubPEM.pem")
	if err != nil {
		return nil, fmt.Errorf("creating ekcert.pem: %v", err)
	}
	defer pubPemFile.Close()
	pubPemFile.Write(pubPEM)

	// convert cert.PublicKey to PEM format
	pubCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(cert.PublicKey.(*rsa.PublicKey)),
	})

	pubCertPEMFile, err := os.Create("pubCertPEM.pem")
	if err != nil {
		return nil, fmt.Errorf("creating ekcert.pem: %v", err)
	}
	defer pubCertPEMFile.Close()
	pubCertPEMFile.Write(pubCertPEM)

	// fmt.Println("EK public key:", string(pubPEM))
	// fmt.Println("EK cert public key:", string(pubCertPEM))
	// fmt.Println("EK cert:", string(certPEM))

	if !reflect.DeepEqual(ekPub, cert.PublicKey) {
		return nil, errors.New("public key in EK certificate differs from public key created via EK template")
	}

	return ekCert, nil
}

func getGCPEKCert(tpmpath string) (string, error) {
	log.Println("Getting GCP EK certificate")
	rwc, err := tpm_conn.TPMConn(tpmpath)
		if err != nil {
			log.Fatal("can't open TPM: {} {} ", tpmpath, err)
		}
	defer rwc.Close()

	var ekcertBytes []byte
	ekk, err := tpm2tools.EndorsementKeyRSA(rwc)
	if err != nil {
		log.Fatal("can't get EK: {}", err)
	}
	defer ekk.Close()

	epubKey := ekk.PublicKey().(*rsa.PublicKey)
	ekBytes, err := x509.MarshalPKIXPublicKey(epubKey)
	if err != nil {
		log.Fatal("can't marshal EK public key: {}", err)
	}

	ekPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: ekBytes,
		},
	)
	log.Println("EK public key:", string(ekPubPEM))
	tpmEkPub, _, _, err := tpm2.ReadPublic(rwc, ekk.Handle())
	if err != nil {
		log.Fatal("can't read EK public key: {}", err)
	}
	_, err = tpmEkPub.Encode()

	ekcertBytes, err = tpm2.NVReadEx(rwc, 0x01c00002, tpm2.HandleOwner, "", 0)
	if err != nil {
		log.Fatal("can't read NV: {}", err)
	}

	encCert, err := x509.ParseCertificate(ekcertBytes)
	if err != nil {
		log.Fatal("can't parse EK cert: {}", err)
	}

	log.Println("EK cert public key:", encCert.Issuer.CommonName)
	return encCert.Issuer.CommonName, nil
}
// signCmd represents the sign command
var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "sign using a tpm",
	Long: ``,
	Run: func(cmd *cobra.Command, args []string) {


		viper.BindPFlags(cmd.Flags())
		tpmpath := viper.GetString("tpm-path")

		cert, err := readEKCert(*&tpmpath, uint32(0x01C00002), uint32(0))
		if err != nil {
			log.Println("Certs don't match, but might be a vtpm thing:", err)
		}

		log.Println("EK certificate:", cert)

		gcp_cert, err := getGCPEKCert(*&tpmpath)
		if err != nil {
			log.Println("something went wrong:", err)
		}
		log.Println("GCP EK certificate:", gcp_cert)
		// Open the file to sign
		signfile := viper.GetString("file")
		if signfile == "" {
			log.Fatal("No file to sign, please pass in a file nanme with --file")
		}

		// Set PCR 23
		pcr := 23

		// Open the TPM device (returns a io.ReadWriteCloser)
		rwc, err := tpm_conn.TPMConn(tpmpath)
		if err != nil {
			log.Fatal("can't open TPM: {} {} ", tpmpath, err)
		}
		defer rwc.Close()
        
		// Flush all existing handles
		totalHandles := 0
		for _, handleType := range handleNames["all"] {
			handles, err := tpm2tools.Handles(rwc, handleType)
			if err != nil {
				log.Fatalf("getting handles: %v", err)
			}
			for _, handle := range handles {
				if err = tpm2.FlushContext(rwc, handle); err != nil {
					log.Fatalf("flushing handle 0x%x: %v", handle, err)
				}
				log.Printf("Handle 0x%x flushed\n", handle)
				totalHandles++
			}
		}

		log.Printf("%d handles flushed\n", totalHandles)

		// Acquire and use PCR23's value to use in auth'd sessions
		pcrList := []int{23}
		pcrval, err := tpm2.ReadPCR(rwc, pcr, tpm2.AlgSHA256)
		if err != nil {
			log.Fatalf("Unable to  ReadPCR : %v", err)
		}
		log.Printf("PCR %v Value %v ", pcr, hex.EncodeToString(pcrval))

		pcrSelection23 := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrList}

		emptyPassword := ""

		// Create EK

		log.Printf("======= createPrimary (EK) ========")

		ekh, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleEndorsement, pcrSelection23, emptyPassword, emptyPassword, defaultEKTemplate)
		if err != nil {
			log.Fatalf("Error creating EK: %v", err)
		}
		defer tpm2.FlushContext(rwc, ekh)

		log.Printf("======= CreateKeyUsingAuth ========")

		sessCreateHandle, _, err := tpm2.StartAuthSession(
			rwc,
			tpm2.HandleNull,
			tpm2.HandleNull,
			make([]byte, 16),
			nil,
			tpm2.SessionPolicy,
			tpm2.AlgNull,
			tpm2.AlgSHA256)
		if err != nil {
			log.Fatalf("Unable to create StartAuthSession : %v", err)
		}
		defer tpm2.FlushContext(rwc, sessCreateHandle)

		// Couples the authorization of an object to that of an existing object without requiring exposing the existing secret until time of object use.
		// https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_policysecret.1.md
		if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, sessCreateHandle, nil, nil, nil, 0); err != nil {
			log.Fatalf("Unable to create PolicySecret: %v", err)
		}

		// Create AK

		authCommandCreateAuth := tpm2.AuthCommand{Session: sessCreateHandle, Attributes: tpm2.AttrContinueSession}

		// CreateKeyUsingAuth creates a new key pair under the owner handle using the provided AuthCommand. 
		// Returns private key "akPriv" and public key blobs "akPub" as well as the creation data, a hash of said data, and the creation ticket.
		akPriv, akPub, _, _, _, err := tpm2.CreateKeyUsingAuth(rwc, ekh, pcrSelection23, authCommandCreateAuth, emptyPassword, defaultKeyParams)
		if err != nil {
			log.Fatalf("Create AKKey failed: %s", err)
		}

		tPub, err := tpm2.DecodePublic(akPub)
		if err != nil {
			log.Fatalf("Error DecodePublic AK %v", tPub)
		}

		ap, err := tPub.Key()
		if err != nil {
			log.Fatalf("akPub.Key() failed: %s", err)
		}
		akBytes, err := x509.MarshalPKIXPublicKey(ap)
		if err != nil {
			log.Fatalf("Unable to convert akPub: %v", err)
		}

		akPubPEM := pem.EncodeToMemory(
			&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: akBytes,
			},
		)

		log.Printf("akPub PEM \n%s", string(akPubPEM))

		// Load the AK into context

		sessLoadHandle, _, err := tpm2.StartAuthSession(
			rwc,
			tpm2.HandleNull,
			tpm2.HandleNull,
			make([]byte, 16),
			nil,
			tpm2.SessionPolicy,
			tpm2.AlgNull,
			tpm2.AlgSHA256)
		if err != nil {
			log.Fatalf("Unable to create StartAuthSession : %v", err)
		}
		defer tpm2.FlushContext(rwc, sessLoadHandle)

		if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, sessLoadHandle, nil, nil, nil, 0); err != nil {
			log.Fatalf("Unable to create PolicySecret: %v", err)
		}
		authCommandLoad := tpm2.AuthCommand{Session: sessLoadHandle, Attributes: tpm2.AttrContinueSession}

		aKkeyHandle, keyName, err := tpm2.LoadUsingAuth(rwc, ekh, authCommandLoad, akPub, akPriv)
		defer tpm2.FlushContext(rwc, aKkeyHandle)
		if err != nil {
			log.Fatalf("Load AK failed: %s", err)
		}
		log.Printf("AK keyName: %v,", hex.EncodeToString(keyName))

		tpm2.FlushContext(rwc, sessLoadHandle)
		tpm2.FlushContext(rwc, sessCreateHandle)

		// Create Child of AK that is Unrestricted (does not have tpm2.FlagRestricted)
		// Under endorsement handle
		log.Printf("======= CreateKeyUsingAuthRestricted ========")

		sessCreateHandle, _, err = tpm2.StartAuthSession(
			rwc,
			tpm2.HandleNull,
			tpm2.HandleNull,
			make([]byte, 16),
			nil,
			tpm2.SessionPolicy,
			tpm2.AlgNull,
			tpm2.AlgSHA256)
		if err != nil {
			log.Fatalf("Unable to create StartAuthSession : %v", err)
		}
		defer tpm2.FlushContext(rwc, sessCreateHandle)

		// if err = tpm2.PolicyPCR(rwc, sessCreateHandle, nil, pcrSelection23); err != nil {
		// 	log.Fatalf("PolicyPCR failed: %v", err)
		// }

		if _, err := tpm2.PolicySecret(rwc, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, sessCreateHandle, nil, nil, nil, 0); err != nil {
			log.Fatalf("Unable to create PolicySecret: %v", err)
		}
		authCommandCreateAuth = tpm2.AuthCommand{Session: sessCreateHandle, Attributes: tpm2.AttrContinueSession}

		// aKdataToSign := []byte("secret")
		fileToSign, err := ioutil.ReadFile(signfile) // just pass the file name
		if err != nil {
			log.Print(err)
		}

		aKdigest, aKvalidation, err := tpm2.Hash(rwc, tpm2.AlgSHA256, fileToSign, tpm2.HandleOwner)
		if err != nil {
			log.Fatalf("Hash failed unexpectedly: %v", err)
		}

		log.Printf("AK Issued Hash %s", base64.StdEncoding.EncodeToString(aKdigest))
		aKsig, err := tpm2.Sign(rwc, aKkeyHandle, emptyPassword, aKdigest, aKvalidation, &tpm2.SigScheme{
			Alg:  tpm2.AlgRSASSA,
			Hash: tpm2.AlgSHA256,
		})
		if err != nil {
			log.Fatalf("Sign failed unexpectedly: %v", err)
		}

		log.Printf("AK Signed Data %s", base64.StdEncoding.EncodeToString(aKsig.RSA.Signature))

		akblock, _ := pem.Decode(akPubPEM)
		if akblock == nil {
			log.Fatalf("Unable to decode akPubPEM %v", err)
		}

		akRsa, err := x509.ParsePKIXPublicKey(akblock.Bytes)
		if err != nil {
			log.Fatalf("Unable to create rsa Key from PEM %v", err)
		}
		akRsaPub := *akRsa.(*rsa.PublicKey)

		akhsh := crypto.SHA256.New()
		akhsh.Write(fileToSign)

		if err := rsa.VerifyPKCS1v15(&akRsaPub, crypto.SHA256, akhsh.Sum(nil), aKsig.RSA.Signature); err != nil {
			log.Fatalf("VerifyPKCS1v15 failed: %v", err)
		}

		log.Printf("AK Verified Signature\n")
		// save akPubPEM to file
		if err := ioutil.WriteFile("public-key.pub", akPubPEM, 0644); err != nil {
			log.Fatalf("Unable to write akPubPEM to file %v", err)
		}

		// write aKsig to file
		if err := ioutil.WriteFile("signature.sig", aKsig.RSA.Signature, 0644); err != nil {
			log.Fatalf("Unable to write aKsig to file %v", err)
		}

		// to verify signature, use openssl

		// openssl dgst -verify public-key.pub -keyform PEM -sha256 -signature signature.sig -binary Vagrantfile

	},
}

func init() {
	rootCmd.AddCommand(signCmd)
	signCmd.PersistentFlags().String("file", "", "A file to sign")
	signCmd.PersistentFlags().String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")	
}
