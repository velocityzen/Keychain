import Foundation
import Testing

@testable import Keychain

@Suite("Values") struct KeychainTests {
    // deinit {
    //     try? keychainDelete("key")
    //     try? keychainDelete("string")
    //     try? keychainDelete("bool")
    // }

    @Test("string") func setAndGetString() async throws {
        let setResult = await keychainSet("string", "value")

        switch setResult {
        case .success:
            break
        case .failure(let error):
            throw error
        }

        let getResult = await keychainGetString("string")
        switch getResult {
        case .success(let value):
            #expect(value == "value")
        case .failure(let error):
            throw error
        }
    }

    @Test("boolean:true/true") func setAndGetBoolTrue() async throws {
        let setResult = await keychainSet("bool", true)

        switch setResult {
        case .success:
            break
        case .failure(let error):
            throw error
        }

        let getResult = await keychainGetBool("bool")
        switch getResult {
        case .success(let value):
            #expect(value == true)
        case .failure(let error):
            throw error
        }
    }

    @Test("boolean:true/false") func setAndFailGetBoolTrue() async throws {
        let setResult = await keychainSet("string bool", "true")

        switch setResult {
        case .success:
            break
        case .failure(let error):
            throw error
        }

        let getResult = await keychainGetBool("string bool")
        #expect(throws: KeychainError.notBoolean) {
            try getResult.get()
        }
    }

    @Test("boolean:false") func setAndGetBoolFalse() async throws {
        let setResult = await keychainSet("bool", false)

        switch setResult {
        case .success:
            break
        case .failure(let error):
            throw error
        }

        let getResult = await keychainGetBool("bool")
        switch getResult {
        case .success(let value):
            #expect(value == false)
        case .failure(let error):
            throw error
        }
    }
}
