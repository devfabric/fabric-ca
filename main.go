package main

import (
	identity "fabric-ca/identity"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func GetCurrentDirectory() (string, error) {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		return "", err
	}
	return strings.Replace(dir, "\\", "/", -1), nil
}

func randomString(strlen int) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, strlen)
	seed := rand.NewSource(time.Now().UnixNano())
	rnd := rand.New(seed)
	for i := 0; i < strlen; i++ {
		result[i] = chars[rnd.Intn(len(chars))]
	}
	return string(result)
}

func main() {
	workDir, err := GetCurrentDirectory()
	if err != nil {
		panic(err)
	}

	//设置环境变量，防止应用未设置
	workDirForFabSDK := os.Getenv("WORKDIR")
	if workDirForFabSDK == "" {
		os.Setenv("WORKDIR", workDir)
	}
	fmt.Println("runDir=", workDir)

	caClient, err := identity.GetMspClient(workDir, "./configs/fabric-ca.yaml")
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	caInfo, err := caClient.GetCAInfo()
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println(string(caInfo.CAChain), caInfo.CAName)

	uname := randomString(32) + "1221231"

	err = caClient.RegisterUser(uname, "12")
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	err = caClient.EnrollUser(uname, "12")
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	// return

	alg, pubKey, err := caClient.GetPubKey(uname)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println(alg, pubKey)

	signature, err := caClient.Sign(uname, []byte("4534534534555555555545454354"))
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	_, cert, err := caClient.GetUserCertificate(uname)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	valid, err := caClient.Verify(string(cert), signature, []byte("4534534534555555555545454354"))
	fmt.Println(valid, err)

	x, err := caClient.LoadX509(uname)
	fmt.Println(string(x), err)

	sig, err := caClient.LocalSign(uname, []byte("4534534534555555555545454354"))
	fmt.Println(sig, err)

	valid, err = caClient.LocalVerify(uname, sig, []byte("4534534534555555555545454354"))
	fmt.Println(valid, err)

}
