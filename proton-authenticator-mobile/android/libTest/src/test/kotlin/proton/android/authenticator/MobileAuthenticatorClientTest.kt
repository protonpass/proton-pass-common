package proton.android.authenticator

import com.google.common.truth.Truth.assertThat
import org.junit.Test
import uniffi.proton_authenticator_common_mobile.AuthenticatorMobileClient

class MobileAuthenticatorClientTest {

    @Test
    fun canInvokeEntryFromUri() {
        val client = AuthenticatorMobileClient()
        val entry =
            client.entryFromUri("otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15")

        assertThat(entry.name).isEqualTo("MYLABEL")
        assertThat(entry.secret).isEqualTo("MYSECRET")
    }

    @Test
    fun serializeAndDeserializePreservesId() {
        val client = AuthenticatorMobileClient()
        val entry =
            client.entryFromUri("otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15")

        val entryId = entry.id
        val serialized = client.serializeEntry(entry)
        val deserialized = client.deserializeEntry(serialized)
        assertThat(deserialized.id).isEqualTo(entryId)
    }

}