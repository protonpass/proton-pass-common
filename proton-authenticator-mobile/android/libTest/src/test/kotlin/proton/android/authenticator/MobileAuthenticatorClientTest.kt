package proton.android.authenticator

import com.google.common.truth.Truth.assertThat
import org.junit.Before
import org.junit.Test
import uniffi.proton_authenticator_common_mobile.AuthenticatorEntrySteamCreateParameters
import uniffi.proton_authenticator_common_mobile.AuthenticatorEntryType
import uniffi.proton_authenticator_common_mobile.AuthenticatorEntryUpdateContents
import uniffi.proton_authenticator_common_mobile.AuthenticatorMobileClient
import uniffi.proton_authenticator_common_mobile.AuthenticatorTotpAlgorithm

class MobileAuthenticatorClientTest {

    private val client = AuthenticatorMobileClient()

    @Test
    fun `can invoke entryFromUri`() {
        val entry = client.entryFromUri(
            "otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15"
        )

        assertThat(entry.name).isEqualTo("MYLABEL")
        assertThat(entry.secret).isEqualTo("MYSECRET")
    }

    @Test
    fun `serialize and deserialize preserves id`() {
        val entry = client.entryFromUri(
            "otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15"
        )

        val entryId = entry.id
        val serialized = client.serializeEntry(entry)
        val deserialized = client.deserializeEntry(serialized)
        assertThat(deserialized.id).isEqualTo(entryId)
    }

    @Test
    fun `can get TOTP params`() {
        val entry = client.entryFromUri(
            "otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15"
        )
        val params = client.getTotpParams(entry)

        assertThat(params.period.toInt()).isEqualTo(15)
        assertThat(params.digits.toInt()).isEqualTo(8)
        assertThat(params.secret).isEqualTo("MYSECRET")
        assertThat(params.algorithm).isEqualTo(AuthenticatorTotpAlgorithm.SHA256)
        assertThat(params.issuer).isEqualTo("MYISSUER")
    }

    @Test
    fun `can generate a TOTP code`() {
        val entry = client.entryFromUri(
            "otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15"
        )

        val codes = client.generateCodes(listOf(entry), 1739284795u)
        assertThat(codes.size).isEqualTo(1)

        val code = codes[0]
        assertThat(code.currentCode).isEqualTo("44326356")
        assertThat(code.nextCode).isEqualTo("14336450")

    }
    
    @Test
    fun `can generate many TOTP codes`() {
        val codes = client.generateCodes(
            entries = listOf(TestUtils.getEntry1(), TestUtils.getEntry2()),
            time = 1739284795u
        )
        assertThat(codes.size).isEqualTo(2)

        val code1 = codes[0]
        assertThat(code1.currentCode).isEqualTo("44326356")
        assertThat(code1.nextCode).isEqualTo("14336450")

        val code2 = codes[1]
        assertThat(code2.currentCode).isEqualTo("02281491")
        assertThat(code2.nextCode).isEqualTo("50598093")
    }

    @Test
    fun `can create steam entry and generate codes`() {
        val name = "MySteamEntry"
        val entry = client.newSteamEntryFromParams(AuthenticatorEntrySteamCreateParameters(
            name = name,
            secret = "STEAMKEY",
            note = null,
        ))

        assertThat(entry.entryType).isEqualTo(AuthenticatorEntryType.STEAM)
        assertThat(entry.issuer).isEqualTo("Steam")
        assertThat(entry.name).isEqualTo(name)

        val codes = client.generateCodes(listOf(entry), 1742298622u)
        assertThat(codes.size).isEqualTo(1)

        val code = codes[0]
        assertThat(code.currentCode).isEqualTo("NTK5M")
        assertThat(code.nextCode).isEqualTo("R9PMC")
    }

    @Test
    fun `can get steam totp params`() {
        val name = "MySteamEntry"
        val entry = client.newSteamEntryFromParams(AuthenticatorEntrySteamCreateParameters(
            name = name,
            secret = "STEAMKEY",
            note = null,
        ))

        val params = client.getTotpParams(entry)
        assertThat(params.algorithm).isEqualTo(AuthenticatorTotpAlgorithm.SHA1)
        assertThat(params.issuer).isEqualTo("Steam")
        assertThat(params.digits.toInt()).isEqualTo(5)
        assertThat(params.period.toInt()).isEqualTo(30)
    }


    @Test
    fun `serialize and deserialize steam entry preserves name`() {
        val name = "MySteamEntry"
        val entry = client.newSteamEntryFromParams(AuthenticatorEntrySteamCreateParameters(
            name = name,
            secret = "STEAMKEY",
            note = null,
        ))

        val serialized = client.serializeEntry(entry)
        val deserialized = client.deserializeEntry(serialized)

        assertThat(deserialized.name).isEqualTo(name)
    }

    @Test
    fun `can update totp entry`() {
        val entry = client.entryFromUri(
            "otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15"
        )

        val initialId = entry.id
        val update = AuthenticatorEntryUpdateContents(
            name = "NEW_NAME",
            secret = "NEW_SECRET",
            issuer = "NEW_ISSUER",
            period = 8u,
            digits = 4.toUByte(),
            algorithm = AuthenticatorTotpAlgorithm.SHA1,
            note = "NEW_NOTE",
            entryType = AuthenticatorEntryType.TOTP
        )
        val updated = client.updateEntry(entry, update)

        assertThat(updated.id).isEqualTo(initialId)
        assertThat(updated.name).isEqualTo(update.name)
        assertThat(updated.issuer).isEqualTo(update.issuer)
        assertThat(updated.period).isEqualTo(update.period)
        assertThat(updated.note).isEqualTo(update.note)
        assertThat(updated.secret).isEqualTo(update.secret)
    }

    @Test
    fun `can update steam entry`() {
        val name = "MySteamEntry"
        val entry = client.newSteamEntryFromParams(AuthenticatorEntrySteamCreateParameters(
            name = name,
            secret = "STEAMKEY",
            note = null,
        ))

        val initialId = entry.id
        val update = AuthenticatorEntryUpdateContents(
            name = "NEW_NAME",
            secret = "JZCVOX2TIVBVERKU",
            note = "NEW_NOTE",

            // These fields are ignored
            issuer = "NEW_ISSUER",
            period = 8u,
            digits = 4.toUByte(),
            algorithm = AuthenticatorTotpAlgorithm.SHA1,
            entryType = AuthenticatorEntryType.STEAM
        )
        val updated = client.updateEntry(entry, update)

        assertThat(updated.id).isEqualTo(initialId)
        assertThat(updated.note).isEqualTo(update.note)
        assertThat(updated.name).isEqualTo(update.name)
        assertThat(updated.secret).isEqualTo(update.secret)
    }

    @Test
    fun `can convert TOTP to steam entry`() {
        val entry = client.entryFromUri(
            "otpauth://totp/MYLABEL?secret=MYSECRET&issuer=MYISSUER&algorithm=SHA256&digits=8&period=15"
        )

        val initialId = entry.id
        val update = AuthenticatorEntryUpdateContents(
            name = "NEW_NAME",
            secret = "JZCVOX2TIVBVERKU",
            note = "NEW_NOTE",

            // These fields are ignored
            issuer = "NEW_ISSUER",
            period = 8u,
            digits = 4.toUByte(),
            algorithm = AuthenticatorTotpAlgorithm.SHA512,
            entryType = AuthenticatorEntryType.STEAM
        )
        val updated = client.updateEntry(entry, update)

        assertThat(updated.id).isEqualTo(initialId)
        assertThat(updated.entryType).isEqualTo(AuthenticatorEntryType.STEAM)
        assertThat(updated.note).isEqualTo(update.note)
        assertThat(updated.name).isEqualTo(update.name)
        assertThat(updated.secret).isEqualTo(update.secret)

        assertThat(updated.period.toInt()).isEqualTo(30) // Period gets ignored
        assertThat(updated.issuer).isEqualTo("Steam") // Issuer gets ignored

        val totpParams = client.getTotpParams(updated)
        assertThat(totpParams.algorithm).isEqualTo(AuthenticatorTotpAlgorithm.SHA1) // Algorithm gets ignored
        assertThat(totpParams.digits.toInt()).isEqualTo(5) // Digits get ignored

    }
}