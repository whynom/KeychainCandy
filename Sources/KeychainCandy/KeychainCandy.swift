import Foundation
import Security

public struct KeychainCandy {
    
    public init() {}
    
    public func addKeychainItem(account: String, service: String, value: String) -> OSStatus {
        
        guard let valueData = value.data(using: .utf8) else {
            return errSecParam
        }
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrService as String: service,
            kSecValueData as String: valueData
        ]
        
        SecItemDelete(query as CFDictionary)
        
        return SecItemAdd(query as CFDictionary, nil)
    }
    
    public func getKeychainItem(account: String, service: String) -> (Int?, OSStatus) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrService as String: service,
            kSecReturnData as String: kCFBooleanTrue!,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var item: AnyObject?
        
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        if status == errSecSuccess,
           let data = item as? Data,
           let valueStr = String(data: data, encoding: .utf8),
           let valueInt = Int(valueStr) {
            return (valueInt, status)
        } else {
            return (nil, status)
        }
    }
}
