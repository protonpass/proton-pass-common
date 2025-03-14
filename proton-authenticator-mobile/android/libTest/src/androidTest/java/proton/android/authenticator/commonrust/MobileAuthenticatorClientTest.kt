package proton.android.authenticator.commonrust

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.common.truth.Truth.assertThat
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class MobileAuthenticatorClientTest {

    @Test
    fun canInvokeEntryFromUri() {
        val client = AuthenticatorMobileClient()
        val entry =
            client.entryFromUri("otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15")

        assertThat(entry.name).isEqualTo("MYLABEL")
    }

}