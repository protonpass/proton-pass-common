package proton.android.authenticator

import proton.android.authenticator.AuthenticatorEntryModel
import proton.android.authenticator.commonrust.AuthenticatorMobileClient
import java.io.File

object TestUtils {

    /** A file of the repository. Gradle runs the tests from libTest/, Bazel from the root (`proton.repo.root`). */
    fun repoFile(path: String): File = File(System.getProperty("proton.repo.root", "../../.."), path)

    fun getEntry1(): AuthenticatorEntryModel {
        val client = AuthenticatorMobileClient()
        return client.entryFromUri("otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15")
    }

    fun getEntry2(): AuthenticatorEntryModel {
        val client = AuthenticatorMobileClient()
        return client.entryFromUri("otpauth://totp/MYLABEL?secret=MYSECRET123&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15")
    }

}