//
//  PinningManager.swift
//  SSLPinning
//
//  Created by Tradesocio on 10/12/21.
//

import Foundation
import Security
import CommonCrypto


class  PinningManager:NSObject,URLSessionDelegate {
    
    static let shared = PinningManager()
    
    var isSSLPinningCerti:Bool = false
    var AlreadyDefind:String = ""
    
    let rsa2048Asn1Header:[UInt8] = [
        0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
    ]
    
    //function to  convert the hash key
    private func sha256(data : Data) -> String {
        var keyWithHeader = Data(rsa2048Asn1Header)
        keyWithHeader.append(data)
        
        var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
        keyWithHeader.withUnsafeBytes {
            _ = CC_SHA256($0, CC_LONG(keyWithHeader.count), &hash)
        }
        return Data(hash).base64EncodedString()
    }
    

    
    //MARK:- URLSessionDelegate
    // basically wirtten to catch the certificates.
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge,nil)
            return
        }
        
        //extarct certificate from each api
        if self.isSSLPinningCerti {
            //compare certificates of remote and local
            let certificateformServer =  SecTrustGetCertificateAtIndex(serverTrust, 2)
            
            let policy = NSMutableArray()
            policy.add(SecPolicyCreateSSL(true, challenge.protectionSpace.host as CFString))
            
            let isSecuredServer = SecTrustEvaluateWithError(serverTrust, nil)
            
            let remoteCertiData:NSData  = SecCertificateCopyData(certificateformServer!)
            
//            guard let pathcertiStackOverflow = Bundle.main.path(forResource: "ISRG Root X1", ofType: "cer") else{
//                fatalError("no local path found")
//            }
            guard let pathcertifacebook = Bundle.main.path(forResource: "GlobalSign", ofType: "cer") else{
                fatalError("no local path found")
            }
            /// comparing the remote certificate data and local certificate data.
            let localCertiData = NSData(contentsOfFile: pathcertifacebook)
            if isSecuredServer && remoteCertiData.isEqual(to:localCertiData! as Data)  {
                print("process completed succesfully")
                
                completionHandler(.useCredential, URLCredential.init(trust: serverTrust))
            }else{
                completionHandler(.cancelAuthenticationChallenge,nil)
            }
        }else{
            //compare Keys
            if let certificate =  SecTrustGetCertificateAtIndex(serverTrust, 2) {
                
                let serverPublicKey = SecCertificateCopyKey(certificate)
                let serverPublicKeyData = SecKeyCopyExternalRepresentation(serverPublicKey!, nil)
                let data:Data = serverPublicKeyData! as Data
                let serverHashKey = sha256(data: data)
                if serverHashKey == self.AlreadyDefind {
                    print("public key Pinning Completed Successfully")
                    completionHandler(.useCredential, URLCredential.init(trust: serverTrust))
                }else{
                    completionHandler(.cancelAuthenticationChallenge,nil)
                    
                }
            }
        }
    }
    
    func callAnyApi(urlString:String,isCertificatePinning:Bool,response:@escaping ((String)-> ())){
        
        let sessionObj = URLSession(configuration: .ephemeral,delegate: self,delegateQueue: nil)
        self.isSSLPinningCerti = isCertificatePinning
        var result:String =  ""
        
        guard let url = URL.init(string: urlString) else {
            fatalError("please add valid url first")
        }
        
        let task = sessionObj.dataTask(with: url) { (data, res, error) in
            
            if  error?.localizedDescription == "cancelled" {
                response("ssl Pinning failed")
            }
            if let data = data {
                let str = String(decoding: data, as: UTF8.self)
                print(str)
                if self.isSSLPinningCerti {
                    response("ssl Pinning successful with Certificate Pinning")
                }else{
                    response("ssl Pinning successful with Public Key  Pinning")
                    
                }
            }
            
        }
        task.resume()
    }
    
}
