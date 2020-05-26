package identity

import (
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hyperledger/fabric-sdk-go/pkg/client/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	providers "github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/cryptosuite"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"github.com/hyperledger/fabric-sdk-go/pkg/util/pathvar"
	"github.com/hyperledger/fabric/bccsp"
	bccspFactory "github.com/hyperledger/fabric/bccsp/factory"
	"github.com/hyperledger/fabric/bccsp/signer"
)

var (
	ErrUserNotFound    = "user not found"
	defaultCfgTemplate = `
version: 1.0.0

client:
  organization: ca.org1.example.com
  logging:
    level: info
  cryptoconfig:
    path: ${WORKDIR}/configs/crypto-config
  credentialStore:
    path: "./configs/key/signcerts"
    cryptoStore:
      path: ./configs/key
  BCCSP:
    security:
      enabled: true
    default:
      provider: "SW"
    hashAlgorithm: "SHA2"
    softVerify: true
    level: 256

organizations:
   ca.org1.example.com:
     mspid: Org1MSP
     cryptoPath:  peerOrganizations/org1.example.com/users/{username}@org1.example.com/msp
     certificateAuthorities:
      - ca.org1.example.com

certificateAuthorities:
  ca.org1.example.com:
    url: http://ca.org1.example.com:7054
    tlsCACerts:
      path: ${WORKDIR}/configs/crypto-config/peerOrganizations/org1.example.com/ca/ca.org1.example.com-cert.pem
      client:
        key:
          path: ${WORKDIR}/configs/crypto-config/peerOrganizations/org1.example.com/ca/80a1b0bdb205aad91b915ad0c2bfeded0b440ea7d32b191155b9b5702b0229e0_sk
        cert:
          path: ${WORKDIR}/configs/crypto-config/peerOrganizations/org1.example.com/ca/ca.org1.example.com-cert.pem
    registrar:
       enrollId: admin
       enrollSecret: adminpw
    caName: ca-org1
`
)

type MspClient struct {
	Sdk             *fabsdk.FabricSDK
	MspClient       *msp.Client
	CAConfig        *providers.CAConfig
	CryptoConfig    core.CryptoSuiteConfig
	MyBCCSP         bccsp.BCCSP
	MSPID           string
	CryptoStorePath string
}

func GetMspClient(workDir string, configPath string) (*MspClient, error) {
	var (
		err      error
		caClient = new(MspClient)
	)

	path := filepath.Join(workDir, configPath)
	configFile, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	//设置环境变量，防止应用未设置
	workDirForFabSDK := os.Getenv("WORKDIR")
	if workDirForFabSDK == "" {
		os.Setenv("WORKDIR", workDir)
	}

	if !checkFileIsExist(configPath) {
		err = ioutil.WriteFile(configFile, []byte(defaultCfgTemplate), 0755)
		if err != nil {
			return nil, err
		}
	}

	configProvider := config.FromFile(pathvar.Subst(configFile))
	configBackend, err := configProvider()
	if err != nil {
		return nil, err
	}

	caClient.CryptoConfig = cryptosuite.ConfigFromBackend(configBackend...)

	// caClient.Sdk, err = fabsdk.New(configProvider)
	caClient.Sdk, err = fabsdk.New(configProvider, fabsdk.WithCryptoSuiteConfig(caClient.CryptoConfig))
	if err != nil {
		return nil, err
	}

	caClient.MspClient, err = msp.New(caClient.Sdk.Context())
	if err != nil {
		return nil, err
	}

	caClient.CAConfig, caClient.MSPID, caClient.CryptoStorePath, err = getAdminCredentials(caClient.Sdk)
	if err != nil {
		return nil, err
	}

	caClient.MyBCCSP, err = initCryptoSuite(caClient.CryptoConfig)
	if err != nil {
		return nil, err
	}
	return caClient, nil
}

func initCryptoSuite(cryptoConfig core.CryptoSuiteConfig) (bccsp.BCCSP, error) {
	config := &bccspFactory.FactoryOpts{
		ProviderName: "SW",
		SwOpts: &bccspFactory.SwOpts{
			HashFamily: cryptoConfig.SecurityAlgorithm(),
			SecLevel:   cryptoConfig.SecurityLevel(),
			Ephemeral:  false,
			FileKeystore: &bccspFactory.FileKeystoreOpts{
				KeyStorePath: cryptoConfig.KeyStorePath(),
			},
		},
	}
	err := bccspFactory.InitFactories(config)
	if err != nil {
		return nil, err
	}

	return bccspFactory.GetDefault(), nil
}

func (mc *MspClient) Destroy() {
	if mc != nil && mc.Sdk != nil {
		mc.Sdk.Close()
	}
}

func getAdminCredentials(sdk *fabsdk.FabricSDK) (*providers.CAConfig, string, string, error) {
	ctxProvider := sdk.Context()
	ctx, err := ctxProvider()
	if err != nil {
		return nil, "", "", err
	}

	orgName := ctx.IdentityConfig().Client().Organization
	caConfig, ok := ctx.IdentityConfig().CAConfig(orgName)
	if !ok {
		return nil, "", "", fmt.Errorf("%s", "CAConfig failed")
	}

	orgConfig, ok := ctx.EndpointConfig().NetworkConfig().Organizations[strings.ToLower(orgName)]
	if !ok {
		return nil, "", "", errors.New("org config retrieval failed")
	}

	cryptoStorePath := ctx.IdentityConfig().Client().CredentialStore.CryptoStore.Path
	return caConfig, orgConfig.MSPID, cryptoStorePath, nil
}

func (mc *MspClient) isExistUser(orgID string) error {
	if mc != nil && mc.Sdk != nil {
		_, err := mc.MspClient.GetSigningIdentity(orgID)
		if err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("%s", "invalid parameter")
}

func (mc *MspClient) enrollAdmin() error {
	registrarEnrollID := mc.CAConfig.Registrar.EnrollID
	registrarEnrollSecret := mc.CAConfig.Registrar.EnrollSecret

	signingIdentity, err := mc.MspClient.GetSigningIdentity(registrarEnrollID)
	if err != nil {
		if err.Error() == ErrUserNotFound {
			err = mc.MspClient.Enroll(registrarEnrollID, msp.WithSecret(registrarEnrollSecret))
			if err != nil {
				return err
			}
			return nil
		}
		return err
	}

	certBytes := signingIdentity.EnrollmentCertificate()
	if certBytes != nil {
		decoded, _ := pem.Decode(certBytes)
		if decoded == nil {
			return errors.New("Failed cert decoding")
		}

		cert, err := x509.ParseCertificate(decoded.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %s", err)
		}

		//证书过期　申请admin证书
		if cert.NotAfter.Before(time.Now().UTC()) {
			err = mc.MspClient.Enroll(registrarEnrollID, msp.WithSecret(registrarEnrollSecret))
			if err != nil {
				return err
			}
			return nil
		}
	}

	return nil
}

func checkFileIsExist(filename string) bool {
	var exist = true
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		exist = false
	}
	return exist
}

func getHashOpt(hashFamily string) (core.HashOpts, error) {
	switch hashFamily {
	case bccsp.SHA2:
		return bccsp.GetHashOpt(bccsp.SHA256)
	case bccsp.SHA3:
		return bccsp.GetHashOpt(bccsp.SHA3_256)
	}
	return nil, fmt.Errorf("hash familiy not recognized [%s]", hashFamily)
}

// local load
func (mc *MspClient) LoadX509(ID string) ([]byte, error) {
	certDir := filepath.Join(mc.CryptoStorePath, "signcerts")
	certFile := filepath.Join(certDir, fmt.Sprintf("%s@%s-cert.pem", ID, mc.MSPID))
	if _, err1 := os.Stat(certFile); os.IsNotExist(err1) {
		return nil, core.ErrKeyValueNotFound
	}

	x509Cert, err := ioutil.ReadFile(certFile) // nolint: gas
	if err != nil {
		return nil, err
	}
	if x509Cert == nil {
		return nil, core.ErrKeyValueNotFound
	}

	return x509Cert, nil
}

func GetSignerFromCert(cert *x509.Certificate, bsp bccsp.BCCSP) (bccsp.Key, crypto.Signer, error) {
	if bsp == nil {
		return nil, nil, errors.New("CSP was not initialized")
	}

	certPubK, err := bsp.KeyImport(cert, &bccsp.X509PublicKeyImportOpts{Temporary: true})
	if err != nil {
		return nil, nil, fmt.Errorf("%s %s", "Failed to import certificate's public key", err.Error())
	}

	ski := certPubK.SKI()
	privateKey, err := bsp.GetKey(ski)
	if err != nil {
		return nil, nil, fmt.Errorf("%s %s", "Could not find matching private key for SKI", err.Error())
	}

	if !privateKey.Private() {
		return nil, nil, fmt.Errorf("The private key associated with the certificate with SKI '%s' was not found", hex.EncodeToString(ski))
	}

	signer, err := signer.New(bsp, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%s %s", "Failed to load ski from bccsp", err.Error())
	}
	return privateKey, signer, nil
}
