package ejsonkms

import (
	"encoding/base64"
	"fmt"
	"os"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
)

var (
	kmsClientCache   = make(map[string]kmsiface.KMSAPI)
	kmsClientCacheMu sync.RWMutex
)

func decryptPrivateKeyWithKMS(privateKeyEnc, awsRegion string) (key string, err error) {
	kmsSvc := getKmsClient(awsRegion)

	encryptedValue, err := base64.StdEncoding.DecodeString(privateKeyEnc)

	params := &kms.DecryptInput{
		CiphertextBlob: []byte(encryptedValue),
	}
	resp, err := kmsSvc.Decrypt(params)
	if err != nil {
		return "", fmt.Errorf("unable to decrypt parameter: %v", err)
	}
	return string(resp.Plaintext), nil
}

func encryptPrivateKeyWithKMS(privateKey, kmsKeyID, awsRegion string) (key string, err error) {
	kmsSvc := getKmsClient(awsRegion)
	params := &kms.EncryptInput{
		KeyId:     &kmsKeyID,
		Plaintext: []byte(privateKey),
	}
	resp, err := kmsSvc.Encrypt(params)
	if err != nil {
		return "", fmt.Errorf("unable to encrypt parameter: %v", err)
	}

	encodedPrivKey := base64.StdEncoding.EncodeToString(resp.CiphertextBlob)
	return encodedPrivKey, nil
}

func getKmsClient(awsRegion string) kmsiface.KMSAPI {
	cacheKey := awsRegion + "|" + os.Getenv("FAKE_AWSKMS_URL")

	kmsClientCacheMu.RLock()
	if client, ok := kmsClientCache[cacheKey]; ok {
		kmsClientCacheMu.RUnlock()
		return client
	}
	kmsClientCacheMu.RUnlock()

	kmsClientCacheMu.Lock()
	defer kmsClientCacheMu.Unlock()

	// Double-check after acquiring write lock
	if client, ok := kmsClientCache[cacheKey]; ok {
		return client
	}

	client := newKmsClient(awsRegion)
	kmsClientCache[cacheKey] = client
	return client
}

func newKmsClient(awsRegion string) kmsiface.KMSAPI {
	awsSession := session.Must(session.NewSession())
	awsSession.Config.WithRegion(awsRegion)
	fakeKmsEndpoint := os.Getenv("FAKE_AWSKMS_URL")
	if len(fakeKmsEndpoint) != 0 {
		return kms.New(awsSession, aws.NewConfig().WithEndpoint(fakeKmsEndpoint))
	}
	return kms.New(awsSession)
}
