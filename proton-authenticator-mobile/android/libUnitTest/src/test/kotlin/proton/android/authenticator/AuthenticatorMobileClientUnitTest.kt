package proton.android.authenticator

import com.google.common.truth.Truth.assertThat
import org.junit.Test
import uniffi.proton_authenticator_common_mobile.AuthenticatorMobileClient
import uniffi.proton_authenticator_common_mobile.AuthenticatorTotpAlgorithm

class AuthenticatorMobileClientUnitTest {

    @Test
    fun `check it can parse from uri`() {
        val client = AuthenticatorMobileClient()
        val entry = client.entryFromUri("otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15")

        assertThat(entry.name).isEqualTo("MYLABEL")
        assertThat(entry.secret).isEqualTo("MYSECRET")
        assertThat(entry.issuer).isEqualTo("MYISSUER")

        val params = client.getTotpParams(entry)
        assertThat(params.algorithm).isEqualTo(AuthenticatorTotpAlgorithm.SHA256)
        assertThat(params.period.toLong()).isEqualTo(15)
    }
}