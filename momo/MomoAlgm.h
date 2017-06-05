#pragma once
#include <Base64.h>
#include <Base64String.h>
#include <string>
#include <hash.h>

using namespace std;

#define aes_encode_size(n) (n % AES_BLOCK_SIZE > 0 ? (1 + n / AES_BLOCK_SIZE) * AES_BLOCK_SIZE : n + AES_BLOCK_SIZE)

//Server And Client used ECC GROUP
__declspec(selectany) string gs_strEccGroupData = "MIGCAgEBMCQGByqGSM49AQECGQD//////////////////////////v//7jcwBgQBAAQBAwQxBNtP8Q7AV+muJrB9AoC39DQdpdGx6uBsfZsvL22cViinhEFj0BW+hjRAgqqI2V4vnQIZAP///////////////iby/BcPaUZqdN79jQIBAQAA";

//Server Public Key
__declspec(selectany) unsigned char gs_uchArrSvrPublicKey[] = { 0x04, 0xC5, 0x17, 0x45, 0x1E, 0x5F, 0x69, 0x4B, 0x79, 0xDD, 0x9F, 0xE9, 0xCD, 0xB4, 0x94, 0x79, 0x22, 0x57, 0xEC, 0xE1, 0x83, 0x11, 0x23, 0x40, 0x82, 0xF4, 0x40, 0xD4, 0xB1, 0x33, 0xA3, 0xDA, 0x74, 0x89, 0xB0, 0x52, 0x58, 0x05, 0x02, 0xF3, 0x46, 0x4D, 0x1C, 0xFF, 0x8D, 0x1C, 0x65, 0xAB, 0xF8 };


class CMomoAlgm
{
public:

	CMomoAlgm()
	{
		
	}
	~CMomoAlgm()
	{
	}
	bool InitMomoAlgm()
	{
		if (!MomoCreateKey())
			return false;

		MomoCalcCK();
		MomoCalcX_KV();

		return true;
	}
	string MomoCalcX_SIGN(const unsigned char *pMZip, int nMZipLen, const string &strUserAgent)
	{
		int nSignBuffLen = strUserAgent.length() + nMZipLen + 8;
		unsigned char *puchSignBuffer = new unsigned char[nSignBuffLen];
		
		//useragent + mzip + sharekey
		memcpy(puchSignBuffer, strUserAgent.c_str(), strUserAgent.length());
		memcpy(puchSignBuffer + strUserAgent.length(), pMZip, nMZipLen);
		memcpy(puchSignBuffer + strUserAgent.length() + nMZipLen, m_strShareKey.c_str(), 8);

		//sha1
		SHA_CTX stShaCtx = { 0 };
		unsigned char ucharrSign[20] = { 0 };

		SHA1_Init(&stShaCtx);
		SHA1_Update(&stShaCtx, &puchSignBuffer, nSignBuffLen);
		SHA1_Final(ucharrSign, &stShaCtx);
		delete[] puchSignBuffer;
		
		//base64
		ByteArray oByteTemp;
		oByteTemp.WriteBytes(ucharrSign, sizeof(ucharrSign));
		string strSign = ToBase64String(oByteTemp);

		return strSign;
	}
	bool MomoAesDecrypt(const unsigned char *pAesDecryptData, int nAesDecryptDataLen, string strAesKey, unsigned char *pAesDecryptDataOut, int *pAesDecryptDataOutLen)
	{
		if (pAesDecryptData[0] != 2 || pAesDecryptData[1] != 3 || pAesDecryptData[6] != 0 || (nAesDecryptDataLen - 7) % AES_BLOCK_SIZE)
		{
			return false;
		}

		if (!pAesDecryptDataOut)
			return false;

		if (*pAesDecryptDataOutLen < nAesDecryptDataLen - 7)
			return false;

		//初始化iv向量
		unsigned long ulRandNumber = *(unsigned long *)&pAesDecryptData[2];
		SHA_CTX stShaCtx = { 0 };
		SHA1_Init(&stShaCtx);
		SHA1_Update(&stShaCtx, &ulRandNumber, sizeof(ulRandNumber));
		unsigned char md[100] = { 0 };
		SHA1_Final(md, &stShaCtx);

		unsigned char uchArrIV[AES_BLOCK_SIZE] = { 0 };
		memcpy(uchArrIV, md, AES_BLOCK_SIZE);

		//初始化密码
		unsigned char uchAesKey[AES_BLOCK_SIZE] = { 0 };
		memcpy(uchAesKey, strAesKey.c_str(), strAesKey.length() > AES_BLOCK_SIZE ? AES_BLOCK_SIZE : strAesKey.length());

		AES_KEY stAesKeyCtx;
		AES_set_decrypt_key(uchAesKey, 128, &stAesKeyCtx);

		AES_cbc_encrypt(&pAesDecryptData[7], pAesDecryptDataOut, nAesDecryptDataLen - 7, &stAesKeyCtx, uchArrIV, AES_DECRYPT);

		//去掉padding
		char nPadLen = pAesDecryptDataOut[nAesDecryptDataLen - 7 - 1];
		if (nPadLen == 0) 
			nPadLen = AES_BLOCK_SIZE;

		*pAesDecryptDataOutLen = nAesDecryptDataLen - 7 - nPadLen;

		return true;
	}
	bool MomoAesDecrypt(const unsigned char *pAesDecryptData, int nAesDecryptDataLen, string strAesKey, ByteArray &oAesDecryptDataOutputBytes)
	{
		if (pAesDecryptData[0] != 2 || pAesDecryptData[1] != 3 || pAesDecryptData[6] != 0 || (nAesDecryptDataLen - 7) % AES_BLOCK_SIZE)
		{
			return false;
		}

		int nAesDecryptDataOutLen = nAesDecryptDataLen - 7;
		unsigned char *pAesDecryptDataOut = new unsigned char[nAesDecryptDataOutLen];
		if (!pAesDecryptDataOut)
			return false;

		if (!MomoAesDecrypt(pAesDecryptData, nAesDecryptDataLen, strAesKey, pAesDecryptDataOut, &nAesDecryptDataOutLen))
		{
			delete[]pAesDecryptDataOut;
			return false;
		}

		oAesDecryptDataOutputBytes.WriteBytes(pAesDecryptDataOut, nAesDecryptDataOutLen);

		return true;
	}
	bool MomoAesDecrypt(const string &strAesDecryptBase64Data, string strAesKey, ByteArray &oAesDecryptDataOutputBytes)
	{
		ByteArray oAesDecryptBytes;
		oAesDecryptBytes = FromBase64String(strAesDecryptBase64Data);

		return MomoAesDecrypt(oAesDecryptBytes.GetData(), oAesDecryptBytes.Length(), strAesKey, oAesDecryptDataOutputBytes);
	}
	bool MomoAesCrypt(const unsigned char *pAesCryptData, int nAesCryptDataLen, string strAesKey, unsigned char *pAesCryptDataOut, int *pAesCryptDataOutLen)
	{
		if (*pAesCryptDataOut == NULL)
			return false;

		if (aes_encode_size(nAesCryptDataLen) + 7 > *pAesCryptDataOutLen)
			return false;

		//计算填充
		int nAesCryptDataAdjustLen = aes_encode_size(nAesCryptDataLen);
		int nPad = nAesCryptDataAdjustLen - nAesCryptDataLen;
		unsigned char chPad = (nPad == AES_BLOCK_SIZE ? 0 : nPad);

		unsigned char *pAesCryptBuffer = new unsigned char[nAesCryptDataAdjustLen];
		if (!pAesCryptBuffer)
			return false;

		memcpy(pAesCryptBuffer, pAesCryptData, nAesCryptDataLen);
		memset(pAesCryptBuffer + nAesCryptDataLen, chPad, nPad);

		//随机生成iv向量表
		unsigned long ulRandNum = 0x9cfd3b91;
		unsigned char uchArrIV[AES_BLOCK_SIZE] = { 0 };
		MomoRandAESIV(ulRandNum, uchArrIV);

		//填充密码
		AES_KEY stAesKeyCtx;
		unsigned char uchArrAesKey[AES_BLOCK_SIZE] = { 0 };
		memcpy(uchArrAesKey, strAesKey.c_str(), strAesKey.length() > AES_BLOCK_SIZE ? AES_BLOCK_SIZE : strAesKey.length());
		AES_set_encrypt_key(uchArrAesKey, 128, &stAesKeyCtx);

		AES_cbc_encrypt(pAesCryptBuffer, pAesCryptBuffer, nAesCryptDataAdjustLen, &stAesKeyCtx, uchArrIV, AES_ENCRYPT);

		//momo flag
		pAesCryptDataOut[0] = 2;
		pAesCryptDataOut[1] = 3;

		*(unsigned long *)&pAesCryptDataOut[2] = ulRandNum;
		pAesCryptDataOut[6] = 0;
		memcpy(&pAesCryptDataOut[7], pAesCryptBuffer, nAesCryptDataAdjustLen);
		*pAesCryptDataOutLen = nAesCryptDataAdjustLen + 7;

		delete[]pAesCryptBuffer;

		return true;
	}
	bool MomoAesCrypt(const unsigned char *pAesCryptData, int nAesCryptDataLen, string strAesKey, ByteArray &AesCryptDataOutputBytes)
	{
		int nAesCryptDataOutLen = aes_encode_size(nAesCryptDataLen) + 7;
		
		unsigned char *pAesCryptDataOut = new unsigned char[nAesCryptDataLen];
		if (!pAesCryptDataOut)
			return false;

		if (!MomoAesCrypt(pAesCryptData, nAesCryptDataLen, strAesKey, pAesCryptDataOut, &nAesCryptDataOutLen))
		{
			delete[] pAesCryptDataOut;

			return false;
		}

		AesCryptDataOutputBytes.WriteBytes(pAesCryptDataOut, nAesCryptDataOutLen);

		return true;
	}
	void MomoRandAESIV(unsigned long ulRandNumber, unsigned char uchArrIV[AES_BLOCK_SIZE])
	{
		SHA_CTX stShaCtx = { 0 };
		SHA1_Init(&stShaCtx);
		SHA1_Update(&stShaCtx, &ulRandNumber, sizeof(ulRandNumber));
		unsigned char byArrSha1[100] = { 0 };
		SHA1_Final(byArrSha1, &stShaCtx);

		memcpy(uchArrIV, byArrSha1, AES_BLOCK_SIZE);
	}
	bool MomoCreateKey()
	{
		memset(m_uchArrShareKey, 0, sizeof(m_uchArrShareKey));
		memset(m_uchArrPublicKey, 0, sizeof(m_uchArrPublicKey));
		m_strShareKey.clear();
		m_strPublicKey.clear();

		if (!MomoCreateECDHKey(m_uchArrShareKey, sizeof(m_uchArrShareKey), m_uchArrPublicKey, sizeof(m_uchArrPublicKey)))
		{
			return false;
		}
		
		ByteArray oTempByte;
		oTempByte.WriteBytes(m_uchArrShareKey, sizeof(m_uchArrShareKey));
		m_strShareKey = ToBase64String(oTempByte);

		oTempByte.Clear();
		oTempByte.WriteBytes(m_uchArrPublicKey, sizeof(m_uchArrPublicKey));
		m_strPublicKey = ToBase64String(oTempByte);

		return true;
	}
	string MomoCalcX_KV()
	{
		m_strX_KV = md5((unsigned char *)m_strPublicKey.c_str(), m_strPublicKey.length()).substr(0, 8);

		return m_strX_KV;
	}
	bool MomoCalcCK()
	{
		int nCkLen = aes_encode_size(sizeof(m_uchArrPublicKey)) + 7;

		unsigned char *puchCK = new unsigned char[nCkLen];
		if (!puchCK)
			return false;

		if (!MomoAesCrypt(m_uchArrPublicKey, sizeof(m_uchArrPublicKey), "Iu0WKHFy", puchCK, &nCkLen))
			return false;

		m_CKBytes.Clear();
		m_CKBytes.WriteBytes(puchCK, nCkLen);
		m_strCK = ToBase64String(m_CKBytes);

		return true;
	}
private:

	//注册算法相关的三个函数
	LONG getmykey(ULONGLONG ek, ULONG len, ULONG off)
	{
		LONG c;
		ULONGLONG a = ek*len;
		a += off*off;
		ULONGLONG b = a % 13;
		c = b;
		if (b > 7)
		{
			c = c % 7;
		}
		if (c == 0) c = 7;

		return c;
	}
	void L1Encrypt(unsigned char *in, LONG len, LONG ek, unsigned char *out)
	{
		for (LONG i = 0; i < len; i++)
		{
			LONG key = getmykey(ek, len, i);
			LONG n, m;
			m = n = in[i];
			n = n << key;
			m = m >> (-key & 7);
			m = m^n;
			m = m << 24;
			m = m >> 24;
			if (m == 3)
			{
				m = (m >> (-key & 7)) ^ (m << key);
				m = m << 24;
				m = m >> 24;
			}
			out[i] = m;
		}
	}
	void L2Encrypt(unsigned char *in, LONG len, LONG ek, unsigned char *out)
	{
		ULONGLONG sum = 0;
		LONG c;
		for (LONG i = 0; i < len; i++)
		{
			LONG key = getmykey(ek, len, i);
			sum += 11;
			sum += i*i*i;
			ULONGLONG b = sum % 29;
			c = b;
			if (b > 7)
			{
				c = c % 7;
			}
			if (c == 0) c = 7;
			ULONG k = (-key & 7);
			ULONG n = (in[i] << k ^ in[i] >> key) << 24 >> 24;
			if (n == 3)
			{
				(n << k ^ n >> key) << 24 >> 24;
			}
		}
	}

	bool MomoCreateECDHKey(unsigned char *pShareKey, size_t cbShareKey, unsigned char *pCliPublicKey, size_t cbCliPublicKey)
	{
		//反持久化group结构
		ByteArray oEccData = FromBase64String(gs_strEccGroupData);
		const unsigned char *puchEccData = oEccData.GetData();
		EC_GROUP *_group = d2i_ECPKParameters(NULL, &puchEccData, oEccData.Length());
		if (_group == NULL)
		{
			return false;
		}

		EC_POINT *_point = EC_POINT_new(_group);
		if (_point == NULL)
		{
			EC_GROUP_free(_group);

			return false;
		}

		if (1 != EC_POINT_oct2point(_group, _point, gs_uchArrSvrPublicKey, sizeof(gs_uchArrSvrPublicKey), NULL))
		{
			EC_GROUP_free(_group);
			EC_POINT_free(_point);

			return false;
		}

		EC_KEY *_ecdh = EC_KEY_new();
		if (_ecdh == NULL)
		{
			EC_GROUP_free(_group);
			EC_POINT_free(_point);

			return false;
		}

		EC_KEY_set_group(_ecdh, _group);
		EC_KEY_generate_key(_ecdh);

		int len = 0;
		len = ECDH_compute_key(pShareKey, cbShareKey, _point, _ecdh, NULL);

		len = EC_POINT_point2oct(EC_KEY_get0_group(_ecdh), 
			EC_KEY_get0_public_key(_ecdh), 
			POINT_CONVERSION_UNCOMPRESSED, pCliPublicKey, cbCliPublicKey, NULL);

		EC_POINT_free(_point);
		EC_GROUP_free(_group);
		EC_KEY_free(_ecdh);

		return true;
	}
public:
	unsigned char m_uchArrShareKey[24];
	unsigned char m_uchArrPublicKey[49];
	string m_strShareKey;
	string m_strPublicKey;
	//CK
	ByteArray m_CKBytes;
	string m_strCK;
	//X_KV
	string m_strX_KV;
};