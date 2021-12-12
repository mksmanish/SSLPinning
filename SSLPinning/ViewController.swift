//
//  ViewController.swift
//  SSLPinning
//
//  Created by Tradesocio on 10/12/21.
//

import UIKit

class ViewController: UIViewController {
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
        
//        PinningManager.shared.callAnyApi(urlString: "https://stackoverflow.com", isCertificatePinning: false) { (response) in
//            print(response)
//        }
        
        
//        PinningManager.shared.callAnyApi(urlString: "https://www.facebook.com", isCertificatePinning: true) { (response) in
//            print(response)
//        }
//
        
        PinningManager.shared.callAnyApi(urlString: "https://www.google.com", isCertificatePinning: false) { (response) in
            print(response)
        }

        
        
    }
    
    
}

