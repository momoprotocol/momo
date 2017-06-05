// momo.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <Windows.h>
#include <stdio.h>
#include <time.h>
#include <winhttp.h>
#include <Charset.h>
#include <gzipHelp.h>
#include <ByteArray.h>
#include <HttpHelp.h>
#include <Base64.h>
#include <hash.h>
#include "MomoAlgm.h"

#import "progid:WinHttp.WinHttpRequest.5.1"
using namespace WinHttp;

int _tmain(int argc, _TCHAR* argv[])
{
 //   unsigned char outxx[20] = { 0 };
//    L1Encrypt((unsigned char *)"28771279231", 11, 30082, outxx);
	
	CMomoAlgm oMomoAlgm;

	//初始化ECDH密钥
	oMomoAlgm.MomoCreateKey();
	oMomoAlgm.MomoCalcCK();
	oMomoAlgm.MomoCalcX_KV();

	//读取登录json
    FILE *fpp = fopen("login.txt", "r");
    if (fpp == NULL)
        return 0;
    fseek(fpp, 0, SEEK_END);
    long lLoginData = ftell(fpp);
    fseek(fpp, 0, SEEK_SET);
	unsigned char *puchLoginData = new unsigned char[lLoginData];
	fread(puchLoginData, lLoginData, 1, fpp);
    fclose(fpp);

	//加密
	ByteArray oMZipBytes;
	oMomoAlgm.MomoAesCrypt(puchLoginData, lLoginData, oMomoAlgm.m_strShareKey, oMZipBytes);

    string strmap_id = "3400526523";
    string strcode_version = "2";
    string strUserAgent = "MomoChat/7.5.3 Android/1170 (Lenovo A828t; Android 4.2.1; Gapps 0; zh_CN; 1; LENOVO)";//UTF-8

	CoInitialize(NULL);
	string strResponse;
    IWinHttpRequestPtr winhttp;
    winhttp.CreateInstance(__uuidof(WinHttpRequest));

   // winhttp->SetProxy(2l, "127.0.0.1:8888");
    winhttp->Open("POST", "https://api.immomo.com/api/v2/login?fr=1000447950327", false);
	winhttp->SetRequestHeader("X-SIGN", oMomoAlgm.MomoCalcX_SIGN(oMZipBytes.GetData(), oMZipBytes.Length(), strUserAgent).c_str());
    winhttp->SetRequestHeader("X-LV", "1");
	winhttp->SetRequestHeader("X-KV", oMomoAlgm.m_strX_KV.c_str());
    winhttp->SetRequestHeader("Accept-Language", "zh-CN");
    winhttp->SetRequestHeader("Charset", "UTF-8");
    winhttp->SetRequestHeader("Expect", "100-continue");
    //winhttp->SetRequestHeader("cookie", "SESSIONID=D830E9FE-C432-0114-FA24-107132BBCFD7_G");
    winhttp->SetRequestHeader("User-Agent", strUserAgent.c_str());
    winhttp->SetRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    winhttp->SetRequestHeader("Accept-Encoding", "gzip");

    //urlencode
    CCharset charset;

	string strPostBody = "X-KV="; strPostBody += oMomoAlgm.m_strX_KV.c_str();
    strPostBody += "&code_version=2";
	strPostBody += "&mzip="; strPostBody += charset.URLEncode(ToBase64String(oMZipBytes));
    strPostBody += "&map_id=2560315552";
	strPostBody += "&ck="; strPostBody += charset.URLEncode(oMomoAlgm.m_strCK.c_str());

    winhttp->Send(strPostBody.c_str());

	ByteArray oResponseBodyBytes;
	GetSafeArrayBytes(V_ARRAY(&winhttp->ResponseBody), oResponseBodyBytes);

	//解压
    bstr_t bstrEncoding = winhttp->GetResponseHeader("Content-Encoding");
    string strEncodeType;
    if (bstrEncoding.GetBSTR())
		strEncodeType = bstrEncoding;

	if (strEncodeType.find("gzip") != string::npos)
    {
		UncompResponse(winhttp->ResponseBody, 1, oResponseBodyBytes);
    }
	
	//解密
	ByteArray oDecryptDataBytes;
	oMomoAlgm.MomoAesDecrypt(oResponseBodyBytes.GetData(), oResponseBodyBytes.Length(), oMomoAlgm.m_strShareKey, oDecryptDataBytes);

	//解压
    unsigned char *puchUnzipLoginRespnseBuff = NULL;
    int nUnzipResponseBuffLen = 0;
	int err = inflate_read((unsigned char *)oDecryptDataBytes.GetData(), oDecryptDataBytes.Length(), &puchUnzipLoginRespnseBuff, &nUnzipResponseBuffLen, 1);

	//保存登录结果
    FILE *fp = fopen("response.txt", "a+");
	fwrite(puchUnzipLoginRespnseBuff, nUnzipResponseBuffLen, 1, fp);
	fwrite("\r\n", 2, 1, fp);
    fclose(fp);

	//json格式化
    Json::Reader reader;
    Json::Value root;
	char *szResponseJson = new char[nUnzipResponseBuffLen + 1];
	memset(szResponseJson, 0, nUnzipResponseBuffLen + 1);
	memcpy(szResponseJson, puchUnzipLoginRespnseBuff, nUnzipResponseBuffLen);
	reader.parse(szResponseJson, root);

	delete[]szResponseJson;
	inflate_free(puchUnzipLoginRespnseBuff);


    //修改资料。
    string str_id = root["data"]["momoid"].asString();
    string str_session = root["data"]["session"].asString();
    string str_cookie = string("SESSIONID=") + str_session;
    Json::Value change;
    change["birthday"] = "1981-9-7";
    change["video"] = "[]";
    change["momoid"] = str_id;

    Json::FastWriter writer;
    string strChange = writer.write(change);
	ByteArray oChangeBytes;
	oMomoAlgm.MomoAesCrypt((unsigned char *)strChange.c_str(), strChange.length(), oMomoAlgm.m_strShareKey, oChangeBytes);

    string strEdit = string("https://api.immomo.com/v1/user/edit/edit?fr=") + str_id;
    winhttp->Open("POST", strEdit.c_str(), false);
    winhttp->SetRequestHeader("X-SIGN", oMomoAlgm.MomoCalcX_SIGN(oChangeBytes.GetData(), oChangeBytes.Length(), strUserAgent).c_str());
    winhttp->SetRequestHeader("X-LV", "1");
    winhttp->SetRequestHeader("X-KV", oMomoAlgm.m_strX_KV.c_str());
    winhttp->SetRequestHeader("Accept-Language", "zh-CN");
    winhttp->SetRequestHeader("Charset", "UTF-8");
    winhttp->SetRequestHeader("Expect", "100-continue");
    winhttp->SetRequestHeader("cookie", str_cookie.c_str());
    winhttp->SetRequestHeader("User-Agent", strUserAgent.c_str());
    winhttp->SetRequestHeader("Content-Type", "application/x-www-form-urlencoded");
    winhttp->SetRequestHeader("Accept-Encoding", "gzip");

    strPostBody = "mzip=";
    strPostBody += charset.URLEncode(ToBase64String(oChangeBytes));
    winhttp->Send(strPostBody.c_str());

	//解压
	oResponseBodyBytes.Clear();
	GetSafeArrayBytes(V_ARRAY(&winhttp->ResponseBody), oResponseBodyBytes);
    bstrEncoding = winhttp->GetResponseHeader("Content-Encoding");
    if (bstrEncoding.GetBSTR())
        strEncodeType = bstrEncoding;

    if (strEncodeType.find("gzip") != string::npos)
    {
		UncompResponse(winhttp->ResponseBody, 1, oResponseBodyBytes);
    }

	//解密
	oDecryptDataBytes.Clear();
	oMomoAlgm.MomoAesDecrypt(oResponseBodyBytes.GetData(), oResponseBodyBytes.Length(), oMomoAlgm.m_strShareKey, oDecryptDataBytes);

	//解压
	unsigned char *puchUnzipChangeRespnseBuff = NULL;
	nUnzipResponseBuffLen = 0;
	err = inflate_read((unsigned char *)oDecryptDataBytes.GetData(), oDecryptDataBytes.Length(), &puchUnzipChangeRespnseBuff, &nUnzipResponseBuffLen, 1);

	//成功
	fp = fopen("response.txt", "a+");
	fwrite(puchUnzipChangeRespnseBuff, nUnzipResponseBuffLen, 1, fp);
	fwrite("\r\n", 2, 1, fp);
	fclose(fp);

	//释放
	inflate_free(puchUnzipChangeRespnseBuff);

    return 0;
}

