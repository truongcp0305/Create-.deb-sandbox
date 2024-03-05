package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
)

func main() {
	var (
		key = []byte{}
		err error
	)

	action := "print"
	if len(os.Args) >= 2 {
		action = os.Args[1]
	}

	key, err = os.ReadFile("key.bin")
	if err != nil {
		key, err = generateAESKey()
		if err != nil {
			fmt.Printf("error create new key: %s", err.Error())
			return
		}
	}
	switch action {
	case "print":
		fmt.Println("hello world")
	case "encrypt":
		if len(os.Args) < 4 {
			fmt.Println("Usage: encrypt [input_file] [output_file]")
		}
		inF := os.Args[2]
		outF := os.Args[3]
		err := encryptFile(inF, outF, key)
		if err != nil {
			fmt.Println(err.Error())
		}
	case "decrypt":
		if len(os.Args) < 4 {
			fmt.Println("Usage: decrypt [input_file] [output_file]")
		}
		inF := os.Args[2]
		outF := os.Args[3]
		err := decryptFile(inF, outF, key)
		if err != nil {
			fmt.Println(err.Error())
		}
	case "gen":
		_, err := generateAESKey()
		if err != nil {
			fmt.Println(err.Error())
		}
		fmt.Println("generated new key!")
	default:
		fmt.Println("Unknown action:", action)
	}
}

// encryptFile mã hóa tệp đầu vào và ghi tệp đã mã hóa ra tệp đầu ra
func encryptFile(inputFile, outputFile string, key []byte) error {
	// Đọc dữ liệu từ tệp đầu vào
	inputFileData, err := os.ReadFile(inputFile)
	if err != nil {
		return err
	}

	// Thêm padding vào dữ liệu
	paddedData := padData(inputFileData)

	// Tạo khóa cipher từ khóa
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	// Tạo iv ngẫu nhiên
	iv := make([]byte, aes.BlockSize)
	_, err = rand.Read(iv)
	if err != nil {
		return err
	}

	// Sử dụng chế độ CBC để mã hóa
	stream := cipher.NewCBCEncrypter(block, iv)

	// Mã hóa dữ liệu
	encryptedData := make([]byte, len(paddedData))
	stream.CryptBlocks(encryptedData, paddedData)

	// Ghi dữ liệu đã mã hóa ra tệp đầu ra
	outFile, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer outFile.Close()

	// Ghi iv đến tệp đầu ra (để giải mã)
	_, err = outFile.Write(iv)
	if err != nil {
		return err
	}

	// Ghi dữ liệu đã mã hóa ra tệp đầu ra
	_, err = outFile.Write(encryptedData)
	if err != nil {
		return err
	}

	return nil
}

// decryptFile giải mã tệp đầu vào và ghi tệp đã giải mã ra tệp đầu ra
func decryptFile(inputFile, outputFile string, key []byte) error {
	// Đọc dữ liệu từ tệp đầu vào
	inputFileData, err := os.ReadFile(inputFile)
	if err != nil {
		return err
	}

	// Tạo khóa cipher từ khóa
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	// Tách iv từ dữ liệu đầu vào
	iv := inputFileData[:aes.BlockSize]
	data := inputFileData[aes.BlockSize:]

	// Sử dụng chế độ CBC để giải mã
	stream := cipher.NewCBCDecrypter(block, iv)

	// Giải mã dữ liệu
	decryptedData := make([]byte, len(data))
	stream.CryptBlocks(decryptedData, data)

	// Loại bỏ padding
	decryptedData, err = unpadData(decryptedData)
	if err != nil {
		return err
	}

	// Ghi dữ liệu đã giải mã ra tệp đầu ra
	outFile, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer outFile.Close()

	// Ghi dữ liệu đã giải mã ra tệp đầu ra
	_, err = outFile.Write(decryptedData)
	if err != nil {
		return err
	}

	return nil
}

func padData(data []byte) []byte {
	padding := aes.BlockSize - (len(data) % aes.BlockSize)
	pad := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, pad...)
}

func unpadData(data []byte) ([]byte, error) {
	length := len(data)
	unpadding := int(data[length-1])
	if unpadding > length {
		return nil, errors.New("invalid padding")
	}
	return data[:(length - unpadding)], nil
}

func generateAESKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	err = os.WriteFile("key.bin", key, 0644)
	if err != nil {
		return key, err
	}
	return key, nil
}
