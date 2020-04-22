//
//  Ango.swift
//  TestAngo
//
//  Created by daisuke ebina on 2020/04/21.
//  Copyright © 2020 daisuke ebina. All rights reserved.
//

import UIKit
import CommonCrypto


enum TestAngoError : Error {
    case encryptFailed(String, Any)
    case decryptFailed(String, Any)
    case otherFailed(String, Any)
}

public class TestAngo {

    /// 暗号
static public func aesCBC256Enc(_ data:[UInt8], key:[UInt8]) throws -> Data {
        let keyLength   = size_t(kCCKeySizeAES256)
        let ivLength    = size_t(kCCBlockSizeAES128)
        let cryptDataLength = size_t(data.count + kCCBlockSizeAES128)
        var cryptData = [UInt8](repeating: UInt8.zero, count:ivLength + cryptDataLength)

        let status = SecRandomCopyBytes(kSecRandomDefault, Int(ivLength), UnsafeMutablePointer<UInt8>(mutating: cryptData))
        if (status != 0) {
            print("IV Error, errno: \(status)")
            throw NSError()
        }

        var numBytesEncrypted :size_t = 0
        let cryptStatus = CCCrypt(CCOperation(kCCEncrypt),
                                  CCAlgorithm(kCCAlgorithmAES128),
                                  CCOptions(kCCOptionPKCS7Padding),
                                  key, keyLength,
                                  cryptData,
                                  data, data.count,
                                  &cryptData + ivLength, cryptDataLength,
                                  &numBytesEncrypted)

        if UInt32(cryptStatus) == UInt32(kCCSuccess) {
            cryptData.removeSubrange(numBytesEncrypted+ivLength..<cryptData.count)
        }
        else {
            print("Error: \(cryptStatus)")
            throw NSError()
        }
        return Data(cryptData)
    }

    static public func aesCBC256Dec(_ data: [UInt8], key: [UInt8]) throws -> Data {
        let clearLength = size_t(data.count)
        var clearData   = [UInt8](repeating:0, count:clearLength)

        let keyLength   = size_t(kCCKeySizeAES256)
        let ivLength    = size_t(kCCBlockSizeAES128)

        var numBytesDecrypted :size_t = 0
        let cryptStatus = CCCrypt(CCOperation(kCCDecrypt),
                                  CCAlgorithm(kCCAlgorithmAES128),
                                  CCOptions(kCCOptionPKCS7Padding),
                                  key, keyLength,
                                  data,
                                  UnsafePointer<UInt8>(data) + ivLength, data.count - ivLength,
                                  &clearData, clearLength,
                                  &numBytesDecrypted)

        if UInt32(cryptStatus) == UInt32(kCCSuccess) {
            clearData.removeSubrange(numBytesDecrypted..<clearLength)

        } else {
            print("Error: \(cryptStatus)")
            throw NSError()
        }
        return Data(clearData)
    }

    /// ランダムIV生成
    public static func generateRandamIV() throws -> String {
        return "1234567890123456"
    }
}
