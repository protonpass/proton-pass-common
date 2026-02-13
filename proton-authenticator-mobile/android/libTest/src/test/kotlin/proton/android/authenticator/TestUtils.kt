package proton.android.authenticator

import proton.android.authenticator.AuthenticatorEntryModel
import proton.android.authenticator.commonrust.AuthenticatorMobileClient

object TestUtils {

    fun getEntry1(): AuthenticatorEntryModel {
        val client = AuthenticatorMobileClient()
        return client.entryFromUri("otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15")
    }

    fun getEntry2(): AuthenticatorEntryModel {
        val client = AuthenticatorMobileClient()
        return client.entryFromUri("otpauth://totp/MYLABEL?secret=MYSECRET123&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15")
    }

}