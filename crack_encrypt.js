// ==UserScript==
// @name         一键Hook加密算法
// @namespace    By:亮亮
// @version      1.2
// @description  一键Hook Crypto RSA 几个基本的方法  AES DES 3DES Hmac  SHA
// @author       liangliang
// @match        https://*/*
// @match        http://*/*
// @icon         data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==
// @grant        none
// ==/UserScript==

(function() {
    'use strict';
    console.log("亮亮网页Hook脚本初始化成功");
    //过dubugger
    var constructorEx = constructor;
    Function.prototype.constructor = function(s) {
        if (s == "debugger") {
            return null;
        }
        return constructorEx(s);
    }

    window.SHook = true
    window.IsDebugger = false
    function hex2b64(h) {
        var b64map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        var i;
        var c;
        var ret = "";
        for (i = 0; i + 3 <= h.length; i += 3) {
            c = parseInt(h.substring(i, i + 3), 16);
            ret += b64map.charAt(c >> 6) + b64map.charAt(c & 63);
        }
        if (i + 1 == h.length) {
            c = parseInt(h.substring(i, i + 1), 16);
            ret += b64map.charAt(c << 2);
        } else if (i + 2 == h.length) {
            c = parseInt(h.substring(i, i + 2), 16);
            ret += b64map.charAt(c >> 2) + b64map.charAt((c & 3) << 4);
        }
        while ((ret.length & 3) > 0)
            ret += "=";
        return ret;
    }
    if (window.CryptoJS != undefined) {
        var Crypto = window.CryptoJS
        //AES加解密
        if (Crypto.AES != undefined) {
            var AESencrypt = Crypto.AES.encrypt
            var AESdecrypt = Crypto.AES.decrypt
            window.CryptoJS.AES.encrypt = function() {
                var Data = arguments[0]
                if (Data == "" || window.SHook == false) {
                    return AESencrypt(arguments[0], arguments[1], arguments[2])
                }
                console.log('检测到AES加密：');
                var AESKey = arguments[1]
                var AESIv = arguments[2]["iv"]
                console.log("EnData:" + CryptoJS.enc.Utf8.stringify(Data))
                console.log("AES Key:" + CryptoJS.enc.Utf8.stringify(AESKey))
                console.log("AES Iv:" + CryptoJS.enc.Utf8.stringify(AESIv))
                if (IsDebugger == true) {
                    debugger ;
                }
                console.log("AES加密结果:" + AESencrypt(arguments[0], arguments[1], arguments[2]))
                return AESencrypt(arguments[0], arguments[1], arguments[2])
            }
            window.CryptoJS.AES.decrypt = function() {
                var Data = arguments[0]
                if (Data == "" || window.SHook == false) {
                    return AESdecrypt(arguments[0], arguments[1], arguments[2])
                }
                console.log('检测到AES解密：');
                var AESKey = arguments[1]
                var AESIv = arguments[2]["iv"]
                console.log("DeData:" + Data)
                console.log("AES Key:" + CryptoJS.enc.Utf8.stringify(AESKey))
                console.log("AES Iv:" + CryptoJS.enc.Utf8.stringify(AESIv))
                if (IsDebugger == true) {
                    debugger ;
                }
                console.log("AES解密结果:" + AESdecrypt(arguments[0], arguments[1], arguments[2]))
                return AESdecrypt(arguments[0], arguments[1], arguments[2])
            }
        }
        //DES加解密
        if (Crypto.DES != undefined) {
            var DESencrypt = Crypto.DES.encrypt
            var DESdecrypt = Crypto.DES.decrypt
            window.CryptoJS.DES.encrypt = function() {
                var Data = arguments[0]
                if (Data == "" || window.SHook == false) {
                    return DESencrypt(arguments[0], arguments[1], arguments[2])
                }
                console.log('检测到DES加密：');
                var AESKey = arguments[1]
                var AESIv = arguments[2]["iv"]
                console.log("EnData:" + CryptoJS.enc.Utf8.stringify(Data))
                console.log("AES Key:" + CryptoJS.enc.Utf8.stringify(AESKey))
                console.log("AES Iv:" + CryptoJS.enc.Utf8.stringify(AESIv))
                if (IsDebugger == true) {
                    debugger ;
                }
                console.log("DES加密结果:" + AESencrypt(arguments[0], arguments[1], arguments[2]))
                return AESencrypt(arguments[0], arguments[1], arguments[2])
            }
            window.CryptoJS.DES.decrypt = function() {
                var Data = arguments[0]
                if (Data == "" || window.SHook == false) {
                    return AESdecrypt(arguments[0], arguments[1], arguments[2])
                }
                console.log('检测到DES解密：');
                var AESKey = arguments[1]
                var AESIv = arguments[2]["iv"]
                console.log("DeData:" + Data)
                console.log("AES Key:" + CryptoJS.enc.Utf8.stringify(AESKey))
                console.log("AES Iv:" + CryptoJS.enc.Utf8.stringify(AESIv))
                if (IsDebugger == true) {
                    debugger ;
                }
                console.log("DES解密结果:" + DESdecrypt(arguments[0], arguments[1], arguments[2]))
                return DESdecrypt(arguments[0], arguments[1], arguments[2])
            }
        }
        //3DES加解密
        if (Crypto.TripleDES != undefined) {
            var TripleDESencrypt = Crypto.TripleDES.encrypt
            var TripleDESdecrypt = Crypto.TripleDES.decrypt
            window.CryptoJS.TripleDES.encrypt = function() {
                var Data = arguments[0]
                if (Data == "" || window.SHook == false) {
                    return TripleDESencrypt(arguments[0], arguments[1], arguments[2])
                }
                console.log('检测到TripleDES加密：');
                var AESKey = arguments[1]
                var AESIv = arguments[2]["iv"]
                console.log("EnData:" + CryptoJS.enc.Utf8.stringify(Data))
                console.log("AES Key:" + CryptoJS.enc.Utf8.stringify(AESKey))
                console.log("AES Iv:" + CryptoJS.enc.Utf8.stringify(AESIv))
                if (IsDebugger == true) {
                    debugger ;
                }
                console.log("TripleDES加密结果:" + AESencrypt(arguments[0], arguments[1], arguments[2]))
                return AESencrypt(arguments[0], arguments[1], arguments[2])
            }
            window.CryptoJS.TripleDES.decrypt = function() {
                var Data = arguments[0]
                if (Data == "" || window.SHook == false) {
                    return AESdecrypt(arguments[0], arguments[1], arguments[2])
                }
                console.log('检测到TripleDES解密：');
                var AESKey = arguments[1]
                var AESIv = arguments[2]["iv"]
                console.log("DeData:" + Data)
                console.log("AES Key:" + CryptoJS.enc.Utf8.stringify(AESKey))
                console.log("AES Iv:" + CryptoJS.enc.Utf8.stringify(AESIv))
                if (IsDebugger == true) {
                    debugger ;
                }
                console.log("TripleDES解密结果:" + TripleDESdecrypt(arguments[0], arguments[1], arguments[2]))
                return TripleDESdecrypt(arguments[0], arguments[1], arguments[2])
            }
        }
        //Hmac
        var HMAC_MD5encrypt = Crypto.HmacMD5
        var HMAC_SHA1encrypt = Crypto.HmacSHA1
        var HMAC_SHA256encrypt = Crypto.HmacSHA256
        var HMAC_SHA384encrypt = Crypto.HmacSHA384
        var HMAC_SHA512encrypt = Crypto.HmacSHA512

        if (Crypto.HmacMD5 != undefined) {
            window.CryptoJS.HmacMD5 = function() {
                var Data = arguments[0];
                if (Data == "" || window.SHook == false) {
                    return HMAC_MD5encrypt(arguments[0], arguments[1]);
                }
                ;console.log("检测到HmacMD5加密：");
                var HmacKey = arguments[1];
                console.log("EnData:" + Data);
                console.log("HmacKey:" + HmacKey);
                if (IsDebugger == true) {
                    debugger ;
                }
                console.log("HmacMD5加密:" + HMAC_MD5encrypt(arguments[0], arguments[1]))
                return HMAC_MD5encrypt(arguments[0], arguments[1]);
            }
        }
        if (Crypto.HmacSHA1 != undefined) {
            window.CryptoJS.HmacSHA1 = function() {
                var Data = arguments[0];
                if (Data == "" || window.SHook == false) {
                    return HMAC_SHA1encrypt(arguments[0], arguments[1]);
                }
                ;console.log("检测到HmacSHA1加密：");
                var HmacKey = arguments[1];
                console.log("EnData:" + Data);
                console.log("HmacKey:" + HmacKey);
                if (IsDebugger == true) {
                    debugger ;
                }
                 console.log("HmacSHA1加密:" + HMAC_SHA1encrypt(arguments[0], arguments[1]))
                return HMAC_SHA1encrypt(arguments[0], arguments[1]);
            }
        }
        if (Crypto.HmacSHA256 != undefined) {
            window.CryptoJS.HmacSHA256 = function() {
                var Data = arguments[0];
                if (Data == "" || window.SHook == false) {
                    return HMAC_SHA256encrypt(arguments[0], arguments[1]);
                }
                ;console.log("检测到HmacSHA256加密：");
                var HmacKey = arguments[1];
                console.log("EnData:" + Data);
                console.log("HmacKey:" + HmacKey);
                if (IsDebugger == true) {
                    debugger ;
                }
                console.log("HmacSHA256加密:" + HMAC_SHA256encrypt(arguments[0], arguments[1]))
                return HMAC_SHA256encrypt(arguments[0], arguments[1]);
            }
        }
        if (Crypto.HmacSHA384 != undefined) {
            window.CryptoJS.HmacSHA384 = function() {
                var Data = arguments[0];
                if (Data == "" || window.SHook == false) {
                    return HMAC_SHA384encrypt(arguments[0], arguments[1]);
                }
                ;console.log("检测到HmacSHA384加密：");
                var HmacKey = arguments[1];
                console.log("EnData:" + Data);
                console.log("HmacKey:" + HmacKey);
                if (IsDebugger == true) {
                    debugger ;
                }
                console.log("HmacSHA384加密:" + HMAC_SHA384encrypt(arguments[0], arguments[1]))
                return HMAC_SHA384encrypt(arguments[0], arguments[1]);
            }
        }
        if (Crypto.HmacSHA512 != undefined) {
            window.CryptoJS.HmacSHA512 = function() {
                var Data = arguments[0];
                if (Data == "" || window.SHook == false) {
                    return HMAC_SHA512encrypt(arguments[0], arguments[1]);
                }
                ;console.log("检测到HmacSHA512加密：");
                var HmacKey = arguments[1];
                console.log("EnData:" + Data);
                console.log("HmacKey:" + HmacKey);
                if (IsDebugger == true) {
                    debugger ;
                }
                console.log("HmacSHA512加密:" + HMAC_SHA512encrypt(arguments[0], arguments[1]))
                return HMAC_SHA512encrypt(arguments[0], arguments[1]);
            }
        }
        //Rabbit加解密
        if (Crypto.TripleDES != undefined) {
            var Rabbitencrypt = Crypto.Rabbit.encrypt
            var Rabbitdecrypt = Crypto.Rabbit.decrypt
            window.CryptoJS.Rabbit.encrypt = function() {
                var Data = arguments[0]
                if (Data == "" || window.SHook == false) {
                    return Rabbitencrypt(arguments[0], arguments[1])
                }
                console.log('检测到Rabbit加密：');
                console.log("EnData:" + Data)
                console.log("Key:" + arguments[1])
                if (IsDebugger == true) {
                    debugger ;
                }
                console.log("Rabbit加密:" + Rabbitencrypt(arguments[0], arguments[1]))
                return Rabbitencrypt(arguments[0], arguments[1])
            }
            window.CryptoJS.Rabbit.decrypt = function() {
                var Data = arguments[0]
                if (Data == "" || window.SHook == false) {
                    return Rabbitdecrypt(arguments[0], arguments[1])
                }
                console.log('检测到Rabbit解密：');
                console.log("DeData:" + Data)
                console.log("Key:" + arguments[1])
                if (IsDebugger == true) {
                    debugger ;
                }
                console.log("Rabbit解密:" + Rabbitdecrypt(arguments[0], arguments[1]))
                return Rabbitdecrypt(arguments[0], arguments[1])
            }
        }
        //PBKDF2加解密
        if (Crypto.PBKDF2 != undefined) {
            var PBKDF2encrypt = Crypto.PBKDF2
            window.CryptoJS.PBKDF2 = function() {
                var Data = arguments[0]
                if (Data == "" || window.SHook == false) {
                    return PBKDF2encrypt(arguments[0], arguments[1], arguments[2])
                }
                console.log('检测到PBKDF2加密：');
                console.log("EnData:" + Data)
                console.log("Salt:" + arguments[1])
                console.log("KeySize:" + arguments[2]['keySize'])
                console.log("iterations:" + arguments[2]['iterations'])
                if (IsDebugger == true) {
                    debugger ;
                }
                console.log("PBKDF2加密:" + PBKDF2encrypt(arguments[0], arguments[1], arguments[2]))
                return PBKDF2encrypt(arguments[0], arguments[1], arguments[2])
            }
        }
        //PBKDF2加解密
        if (Crypto.EvpKDF != undefined) {
            var EvpKDFencrypt = Crypto.EvpKDF
            window.CryptoJS.EvpKDF = function() {
                var Data = arguments[0]
                if (Data == "" || window.SHook == false) {
                    return EvpKDFencrypt(arguments[0], arguments[1], arguments[2])
                }
                console.log('检测到EvpKDF加密：');
                console.log("EnData:" + Data)
                console.log("Salt:" + arguments[1])
                console.log("KeySize:" + arguments[2]['keySize'])
                console.log("iterations:" + arguments[2]['iterations'])
                if (IsDebugger == true) {
                    debugger ;
                }
                console.log("EvpKDF加密:" + EvpKDFencrypt(arguments[0], arguments[1], arguments[2]))
                return EvpKDFencrypt(arguments[0], arguments[1], arguments[2])
            }
        }
        //Md5加密
        if (Crypto.MD5 != undefined) {
            var MD5encrypt = Crypto.MD5
            window.CryptoJS.MD5 = function() {
                var Data = arguments[0]
                if (Data == "" || window.SHook == false) {
                    return MD5encrypt(arguments[0])
                }
                console.log('检测到MD5加密：');
                console.log("EnData:" + Data)
                if (IsDebugger == true) {
                    debugger ;
                }
                console.log("MD5加密:" + MD5encrypt(arguments[0]))
                return MD5encrypt(arguments[0])
            }
        }
        //SHA1加密
        if (Crypto.SHA1 != undefined) {
            var SHA1encrypt = Crypto.SHA1
            window.CryptoJS.SHA1 = function() {
                var Data = arguments[0]
                if (Data == "" || window.SHook == false) {
                    return SHA1encrypt(arguments[0])
                }
                console.log('检测到SHA1加密：');
                console.log("EnData:" + Data)
                if (IsDebugger == true) {
                    debugger ;
                }
                console.log("SHA1加密:" + SHA1encrypt(arguments[0]))
                return SHA1encrypt(arguments[0])
            }
        }
        //SHA3加密
        if (Crypto.SHA3 != undefined) {
            var SHA3encrypt = Crypto.SHA3
            window.CryptoJS.SHA3 = function() {
                var Data = arguments[0]
                if (Data == "" || window.SHook == false) {
                    return SHA3encrypt(arguments[0])
                }
                console.log('检测到SHA3加密：');
                console.log("EnData:" + Data)
                if (IsDebugger == true) {
                    debugger ;
                }
                console.log("SHA3加密:" + SHA3encrypt(arguments[0]))
                return SHA3encrypt(arguments[0])
            }
        }
        //SHA224加密
        if (Crypto.SHA224 != undefined) {
            var SHA224encrypt = Crypto.SHA224
            window.CryptoJS.SHA224 = function() {
                var Data = arguments[0]
                if (Data == "" || window.SHook == false) {
                    return SHA224encrypt(arguments[0])
                }
                console.log('检测到SHA224加密：');
                console.log("EnData:" + Data)
                if (IsDebugger == true) {
                    debugger ;
                }
                console.log("SHA224加密:" + SHA224encrypt(arguments[0]))
                return SHA224encrypt(arguments[0])
            }
        }
        //SHA256加密
        if (Crypto.SHA256 != undefined) {
            var SHA256encrypt = Crypto.SHA256
            window.CryptoJS.SHA256 = function() {
                var Data = arguments[0]
                if (Data == "" || window.SHook == false) {
                    return SHA256encrypt(arguments[0])
                }
                console.log('检测到SHA256加密：');
                console.log("EnData:" + Data)
                if (IsDebugger == true) {
                    debugger ;
                }
                console.log("SHA256加密:" + SHA256encrypt(arguments[0]))
                return SHA256encrypt(arguments[0])
            }
        }
        //SHA384加密
        if (Crypto.SHA384 != undefined) {
            var SHA384encrypt = Crypto.SHA384
            window.CryptoJS.SHA384 = function() {
                var Data = arguments[0]
                if (Data == "" || window.SHook == false) {
                    return SHA384encrypt(arguments[0])
                }
                console.log('检测到SHA384加密：');
                console.log("EnData:" + Data)
                if (IsDebugger == true) {
                    debugger ;
                }
                console.log("SHA384加密:" + SHA384encrypt(arguments[0]))
                return SHA384encrypt(arguments[0])
            }
        }
        //SHA512加密
        if (Crypto.SHA512 != undefined) {
            var SHA512encrypt = Crypto.SHA512
            window.CryptoJS.SHA512 = function() {
                var Data = arguments[0]
                if (Data == "" || window.SHook == false) {
                    return SHA512encrypt(arguments[0])
                }
                console.log('检测到SHA512加密：');
                console.log("EnData:" + Data)
                if (IsDebugger == true) {
                    debugger ;
                }
                console.log("SHA512加密:" + SHA512encrypt(arguments[0]))
                return SHA512encrypt(arguments[0])
            }
        }
        //RIPEMD160加密
        if (Crypto.RIPEMD160encrypt != undefined) {
            var RIPEMD160encrypt = Crypto.RIPEMD160
            window.CryptoJS.RIPEMD160 = function() {
                var Data = arguments[0]
                if (Data == "" || window.SHook == false) {
                    return RIPEMD160encrypt(arguments[0])
                }
                console.log('检测到RIPEMD160加密：');
                console.log("EnData:" + Data)
                if (IsDebugger == true) {
                    debugger ;
                }
                 console.log("RIPEMD160加密:" + RIPEMD160encrypt(arguments[0]))
                return RIPEMD160encrypt(arguments[0])
            }
        }
    }
    //RSA  加解密
    if (window.biToHex != undefined) {
        var ToHex = window.biToHex
        if (window.encryptedString != undefined) {
            var RsaEncrypt = window.encryptedString
            window.encryptedString = function() {
                var KeyPair = arguments[0];
                var Data = arguments[1]
                if (Data == "" || window.SHook == false) {
                    return RsaEncrypt(KeyPair, Data)
                }
                console.log('检测到RSA加密：');
                var PublicKey = ToHex(KeyPair.e).substr(2)
                //取右边6位就是公钥了
                var Modulus = "00" + ToHex(KeyPair.m);
                //前面补俩个0
                console.log("EnData:" + Data);
                console.log("PublicKey:" + PublicKey);
                console.log("Modulus:" + Modulus);
                if (IsDebugger == true) {
                    debugger ;
                }
                console.log("RSA加密:" + RsaEncrypt(KeyPair, Data))
                return RsaEncrypt(KeyPair, Data)
            }
        }
        if (window.decryptedString != undefined) {
            var RsaDecrypt = window.decryptedString
            window.decryptedString = function() {
                var KeyPair = arguments[0];
                var Data = arguments[1]
                if (Data == "" || window.SHook == false) {
                    return RsaEncrypt(KeyPair, Data)
                }
                console.log('检测到RSA加密：');
                var PublicKey = ToHex(KeyPair.e).substr(2)
                //取右边6位就是公钥了
                var Modulus = "00" + ToHex(KeyPair.m);
                //前面补俩个0
                console.log("EnData:" + Data);
                console.log("PublicKey:" + PublicKey);
                console.log("Modulus:" + Modulus);
                if (IsDebugger == true) {
                    debugger ;
                }
                console.log("RSA加密:" + RsaDecrypt(KeyPair, Data))
                return RsaDecrypt(KeyPair, Data)
            }
        }
    }
    if (window.JSEncrypt != undefined) {
        var RSA = window.JSEncrypt.prototype
        if (RSA.encrypt != undefined) {
            var RSA_encrypt = RSA.encrypt
            window.JSEncrypt.prototype.encrypt = function() {
                var Data = arguments[0]
                if (Data == "" || window.SHook == false) {
                    return hex2b64(RSA.key.encrypt(Data))
                }
                console.log('检测到RSA加密：');
                console.log('EnData：' + Data);
                if (IsDebugger == true) {
                    debugger ;
                }
                console.log("RSA加密:" + hex2b64(RSA.key.encrypt(Data)))
                return hex2b64(RSA.key.encrypt(Data))
            }
        }
        if (RSA.decrypt != undefined) {
            var RSA_decrypt = RSA.decrypt
            window.JSEncrypt.prototype.decrypt = function() {
                var Data = arguments[0]
                if (Data == "" || window.SHook == false) {
                    return hex2b64(RSA.key.decrypt(Data))
                }
                console.log('检测到RSA解密：');
                console.log('DeData：' + Data);
                if (IsDebugger == true) {
                    debugger ;
                }
                console.log("RSA解密:" + hex2b64(RSA.key.decrypt(Data)))
                return hex2b64(RSA.key.decrypt(Data))
            }
        }
        if (RSA.setPublicKey != undefined) {
            var RSA_setPublicKey = RSA.setPublicKey
            window.JSEncrypt.prototype.setPublicKey = function() {
                var Data = arguments[0]
                if (Data == "" || window.SHook == false) {
                    return RSA.setKey(Data)
                    return
                }
                console.log('检测到RSA设置公钥：');
                console.log('PublicKey：' + Data);
                if (IsDebugger == true) {
                    debugger ;
                }
                return RSA.setKey(Data)
            }
        }
        if (RSA.setPrivateKey != undefined) {
            var RSA_setPrivateKey = RSA.setPrivateKey
            window.JSEncrypt.prototype.setPrivateKey = function() {
                var Data = arguments[0]
                if (Data == "" || window.SHook == false) {
                    return RSA.setKey(Data)
                }
                console.log('检测到RSA设置私钥：');
                console.log('PrivateKey：' + Data);
                if (IsDebugger == true) {
                    debugger ;
                }
                return RSA.setKey(Data)
            }
        }

    }
}
)();
