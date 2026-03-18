package proton.android.pass

import com.google.common.truth.Truth.assertThat
import kotlinx.coroutines.delay
import org.junit.Test
import proton.android.pass.commonrust.MobileFetchException
import proton.android.pass.commonrust.MobileWebauthnClientFetcher
import proton.android.pass.commonrust.MobileWebauthnDomainsResponse
import proton.android.pass.commonrust.PasskeyManager
import kotlin.test.assertFailsWith

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
        var invoked = false
        val fetcher = object : MobileWebauthnClientFetcher {
            override suspend fun fetch(url: String): MobileWebauthnDomainsResponse {
                // Suspend function to check for await
                delay(100)
                invoked = true
                return MobileWebauthnDomainsResponse(
                    origins = listOf("https://aliexpress.com", "https://m.aliexpress.com")
                )
            }
        }

        val manager = PasskeyManager()
        manager.registerWebauthnFetcher(fetcher)

        val relatedOriginRequest = """
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
        val result = manager.generatePasskey("https://aliexpress.com", relatedOriginRequest)

        assertThat(result.passkey).isNotEmpty()
        assertThat(result.keyId).isNotEmpty()
        assertThat(result.response).isNotEmpty()
        assertThat(result.rpId).isEqualTo("m.aliexpress.com")
        assertThat(invoked).isTrue()
    }

    @Test
    fun `fetcher NotFound error is propagated as generation exception`() {
        val fetcher = object : MobileWebauthnClientFetcher {
            override suspend fun fetch(url: String): MobileWebauthnDomainsResponse {
                throw MobileFetchException.NotFound("not found")
            }
        }

        val manager = PasskeyManager()
        manager.registerWebauthnFetcher(fetcher)

        val relatedOriginRequest = """
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

        assertFailsWith<Exception> {
            manager.generatePasskey("https://aliexpress.com", relatedOriginRequest)
        }
    }

    @Test
    fun `fetcher CannotFetch error is propagated as generation exception`() {
        val fetcher = object : MobileWebauthnClientFetcher {
            override suspend fun fetch(url: String): MobileWebauthnDomainsResponse {
                throw MobileFetchException.CannotFetch("network error")
            }
        }

        val manager = PasskeyManager()
        manager.registerWebauthnFetcher(fetcher)

        val relatedOriginRequest = """
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

        assertFailsWith<Exception> {
            manager.generatePasskey("https://aliexpress.com", relatedOriginRequest)
        }
    }
}
