package proton.android.pass

import com.google.common.truth.Truth.assertThat
import org.junit.Test
import proton.android.pass.commonrust.MobileWebauthnClientFetcher
import proton.android.pass.commonrust.MobileWebauthnDomainsResponse
import proton.android.pass.commonrust.PasskeyManager

class PasskeyTest {

    private val webauthnIoRequest = """
        {
            "attestation": "none",
            "authenticatorSelection": {
                "residentKey": "preferred",
                "userVerification": "preferred"
            },
            "challenge": "D-5y7y_E4V8NQBJrFnnhd7NCvRGhO5sBGwzfh23y8D4a_hSMyRRuTAp0hmSm6_eimM71XoYF84VUiY8e9kqavA",
            "excludeCredentials": [],
            "pubKeyCredParams": [
                {"alg": -7, "type": "public-key"},
                {"alg": -257, "type": "public-key"}
            ],
            "rp": {"id": "webauthn.io", "name": "webauthn.io"},
            "user": {"displayName": "testuser", "id": "ZFhsbmRYbG9hZw", "name": "testuser"}
        }
    """.trimIndent()

    private val relatedOriginRequest = """
        {
            "challenge": "dGVzdGNoYWxsZW5nZQ==",
            "rp": {"id": "m.aliexpress.com", "name": "AliExpress"},
            "user": {
                "id": "dXNlcklk",
                "name": "user@example.com",
                "displayName": "Test User"
            },
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            "timeout": 60000
        }
    """.trimIndent()

    @Test
    fun `can generate passkey without fetcher`() {
        val manager = PasskeyManager()

        val result = manager.generatePasskey("https://webauthn.io", webauthnIoRequest)

        assertThat(result.passkey).isNotEmpty()
        assertThat(result.keyId).isNotEmpty()
        assertThat(result.response).isNotEmpty()
    }

    @Test
    fun `can register fetcher and generate passkey with related origin`() {
        val fetcher = object : MobileWebauthnClientFetcher {
            override suspend fun fetch(url: String): MobileWebauthnDomainsResponse {
                return MobileWebauthnDomainsResponse(
                    origins = listOf("https://aliexpress.com", "https://m.aliexpress.com")
                )
            }
        }

        val manager = PasskeyManager()
        manager.registerWebauthnFetcher(fetcher)
        val result = manager.generatePasskey("https://aliexpress.com", relatedOriginRequest)

        assertThat(result.passkey).isNotEmpty()
        assertThat(result.keyId).isNotEmpty()
        assertThat(result.response).isNotEmpty()
    }
}
