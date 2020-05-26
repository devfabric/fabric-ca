package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/hyperledger/fabric-sdk-go/pkg/client/msp"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	"github.com/hyperledger/fabric/bccsp"
)

func (mc *MspClient) GetCAInfo() (*msp.GetCAInfoResponse, error) {
	if mc != nil && mc.MspClient != nil {
		resp, err := mc.MspClient.GetCAInfo()
		if err != nil {
			return nil, err
		}
		return resp, nil
	}
	return nil, fmt.Errorf("%s", "invalid parameter")
}

func (mc *MspClient) RegisterUser(ID, secret string) error {
	if mc != nil && mc.MspClient != nil {
		err := mc.enrollAdmin()
		if err != nil {
			return err
		}

		_, err = mc.MspClient.Register(&msp.RegistrationRequest{
			Name:        ID,
			Type:        "client",
			Affiliation: "org1",
			Secret:      secret,
			CAName:      mc.CAConfig.CAName,
		})
		if err != nil {
			return err
		}
		return nil
	}

	return fmt.Errorf("%s", "invalid parameter")
}

func (mc *MspClient) EnrollUser(ID, secret string) error {
	if mc != nil && mc.MspClient != nil {
		err := mc.enrollAdmin()
		if err != nil {
			return err
		}

		err = mc.MspClient.Enroll(ID, msp.WithSecret(secret))
		if err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("%s", "invalid parameter")
}

func (mc *MspClient) Reenroll(ID string, secret string) error {
	if mc != nil && mc.MspClient != nil {
		err := mc.enrollAdmin()
		if err != nil {
			return err
		}

		err = mc.MspClient.Reenroll(ID, msp.WithSecret(secret))
		if err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("%s", "invalid parameter")
}

func (mc *MspClient) Revoke(ID string) error {
	if mc != nil && mc.MspClient != nil {
		err := mc.enrollAdmin()
		if err != nil {
			return err
		}

		x509, _, err := mc.GetUserCertificate(ID)
		if err != nil {
			return err
		}

		_, err = mc.MspClient.Revoke(&msp.RevocationRequest{
			Name:   ID,
			Serial: x509.SerialNumber.String(),
			Reason: "过期",
			CAName: mc.CAConfig.CAName,
		})
		if err != nil {
			return err
		}
	}
	return fmt.Errorf("%s", "invalid parameter")
}

func (mc *MspClient) GetPubKey(ID string) (string, string, error) {
	if mc != nil && mc.MspClient != nil {
		x509Cert, _, err := mc.GetUserCertificate(ID)
		if err != nil {
			return "", "", err
		}

		if x509Cert.PublicKeyAlgorithm == x509.ECDSA {
			ecdsaPublicKey := x509Cert.PublicKey.(*ecdsa.PublicKey)
			x509EncodedPub, _ := x509.MarshalPKIXPublicKey(ecdsaPublicKey)
			pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})
			return x509Cert.PublicKeyAlgorithm.String(), string(pemEncodedPub), nil
		}
	}
	return "", "", fmt.Errorf("%s", "invalid parameter")
}

func ParsePubKey(alg string, pubKey string) interface{} {
	blockPub, _ := pem.Decode([]byte(pubKey))
	x509EncodedPub := blockPub.Bytes
	genericPublicKey, _ := x509.ParsePKIXPublicKey(x509EncodedPub)

	if alg == "ECDSA" {
		// _ = genericPublicKey.(*ecdsa.PublicKey)
		return genericPublicKey
	}

	return nil
}

func (mc *MspClient) GetUserCertificate(orgID string) (*x509.Certificate, []byte, error) {
	signingIdentity, err := mc.MspClient.GetSigningIdentity(orgID)
	if err != nil {
		return nil, nil, err
	}

	certBytes := signingIdentity.EnrollmentCertificate()
	if certBytes != nil {
		decoded, _ := pem.Decode(certBytes)
		if decoded == nil {
			return nil, nil, errors.New("Failed cert decoding")
		}

		cert, err := x509.ParseCertificate(decoded.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse certificate: %s", err)
		}

		return cert, certBytes, nil
	}
	return nil, nil, nil
}

func (mc *MspClient) Sign(ID string, digest []byte) (string, error) {
	ctxProvider := mc.Sdk.Context(fabsdk.WithUser(ID))

	ctx, err := ctxProvider()
	if err != nil {
		return "", err
	}

	signingMgr := ctx.SigningManager()
	signature, err := signingMgr.Sign(digest, ctx.PrivateKey())
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

func (mc *MspClient) Verify(certificate string, signature string, digest []byte) (bool, error) {
	var (
		err   error
		valid bool
	)

	cert, _ := pem.Decode([]byte(certificate))
	cert509, err := x509.ParseCertificate(cert.Bytes) // 获取法国用户名
	if err != nil {
		return valid, err
	}

	//获取公钥
	pubKey, err := mc.MyBCCSP.KeyImport(cert509, &bccsp.X509PublicKeyImportOpts{Temporary: true})
	if err != nil {
		return valid, err
	}
	if pubKey == nil {
		return valid, fmt.Errorf("%s", "failed importing public key.")
	}

	//解码
	signBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return valid, err
	}

	hashOpt, err := getHashOpt(mc.CryptoConfig.SecurityAlgorithm())
	if err != nil {
		return valid, err
	}

	//hash
	hashDigest, err := mc.MyBCCSP.Hash(digest, hashOpt)
	if err != nil {
		return valid, err
	}

	//校验
	valid, err = mc.MyBCCSP.Verify(pubKey, signBytes, hashDigest, nil)
	if err != nil {
		return valid, err
	}

	return valid, nil
}

func (mc *MspClient) LocalSign(ID string, digest []byte) (string, error) {
	var (
		err    error
		signed []byte
	)

	certificate, err := mc.LoadX509(ID)
	if err != nil {
		return "", err
	}

	cert, _ := pem.Decode([]byte(certificate))
	cert509, err := x509.ParseCertificate(cert.Bytes) // 获取法国用户名
	if err != nil {
		return "", err
	}

	_, siger, err := GetSignerFromCert(cert509, mc.MyBCCSP)
	if err != nil {
		return "", err
	}

	h := crypto.SHA256.New()
	h.Write(digest)
	signed = h.Sum(nil)

	signature, err := siger.Sign(rand.Reader, signed, crypto.SHA256)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

func (mc *MspClient) LocalVerify(ID string, signature string, digest []byte) (bool, error) {
	var (
		err   error
		valid bool
	)

	certificate, err := mc.LoadX509(ID)
	if err != nil {
		return valid, err
	}

	cert, _ := pem.Decode([]byte(certificate))
	cert509, err := x509.ParseCertificate(cert.Bytes) // 获取法国用户名
	if err != nil {
		return valid, err
	}

	//获取公钥
	pubKey, err := mc.MyBCCSP.KeyImport(cert509, &bccsp.X509PublicKeyImportOpts{Temporary: true})
	if err != nil {
		return valid, err
	}
	if pubKey == nil {
		return valid, fmt.Errorf("%s", "failed importing public key.")
	}

	//解码
	signBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return valid, err
	}

	hashOpt, err := getHashOpt(mc.CryptoConfig.SecurityAlgorithm())
	if err != nil {
		return valid, err
	}

	//hash
	hashDigest, err := mc.MyBCCSP.Hash(digest, hashOpt)
	if err != nil {
		return valid, err
	}

	//校验
	valid, err = mc.MyBCCSP.Verify(pubKey, signBytes, hashDigest, nil)
	if err != nil {
		return valid, err
	}

	return valid, nil
}
