package proton.android.authenticator

import com.google.common.truth.Truth.assertThat
import org.junit.Test
import uniffi.proton_authenticator_common_mobile.LocalEntry
import uniffi.proton_authenticator_common_mobile.LocalEntryState
import uniffi.proton_authenticator_common_mobile.OperationType
import uniffi.proton_authenticator_common_mobile.RemoteEntry
import uniffi.proton_authenticator_common_mobile.SyncOperationChecker

class SyncOperationCheckerTest {

    private val instance = SyncOperationChecker()

    @Test
    fun `can handle empty lists`() {
        val res = instance.calculateOperations(emptyList(), emptyList())
        assertThat(res).isEmpty()
    }

    @Test
    fun `does not return anything in case no differences`() {
        val entry = TestUtils.getEntry1()
        val remote = listOf(RemoteEntry(remoteId = "REMOTE_ID", entry = entry, modifyTime = NOW))
        val local = listOf(LocalEntry(
            entry = entry,
            state = LocalEntryState.SYNCED,
            modifyTime = NOW,
            localModifyTime = null
        ))
        val res = instance.calculateOperations(remote, local)
        assertThat(res).isEmpty()
    }

    @Test
    fun `remote entry not present in local returns upsert`() {
        val entry = TestUtils.getEntry1()
        val remoteId = "REMOTE_ID"
        val remote = listOf(RemoteEntry(remoteId = remoteId, entry = entry, modifyTime = NOW))
        val res = instance.calculateOperations(remote, emptyList())

        assertThat(res.size).isEqualTo(1)
        assertThat(res[0].entry).isEqualTo(entry)
        assertThat(res[0].remoteId).isEqualTo(remoteId)
        assertThat(res[0].operation).isEqualTo(OperationType.UPSERT)
    }

    @Test
    fun `local entry pending to be pushed not present in remote returns push`() {
        val entry = TestUtils.getEntry1()
        val local = listOf(LocalEntry(
            entry = entry,
            state = LocalEntryState.PENDING_SYNC,
            modifyTime = NOW,
            localModifyTime = null
        ))
        val res = instance.calculateOperations(emptyList(), local)

        assertThat(res.size).isEqualTo(1)
        assertThat(res[0].entry).isEqualTo(entry)
        assertThat(res[0].remoteId).isNull()
        assertThat(res[0].operation).isEqualTo(OperationType.PUSH)
    }

    companion object {
        private val NOW = 1_700_000_000L
    }

}