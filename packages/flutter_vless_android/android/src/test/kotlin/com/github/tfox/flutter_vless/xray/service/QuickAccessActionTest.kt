package com.github.tfox.flutter_vless.xray.service

import org.junit.Assert.*
import org.junit.Test

class QuickAccessActionTest {
    private val enabled = NativeVlessOptions(quickAccess = NativeVlessOptions.QuickAccess(enabled=true))
    private val revision = "a".repeat(32)
    private val start = QuickAccessAction(revision,"toggle",QuickAccessAction.Operation.START,profile="b".repeat(64))
    @Test fun unchangedActionRequiresTheOriginalRevisionAndUnlock() {
        assertTrue(start.permits(QuickAccessSnapshot(enabled,revision),false))
        assertFalse(start.permits(QuickAccessSnapshot(enabled,revision),true))
        assertFalse(start.permits(QuickAccessSnapshot(enabled,"c".repeat(32)),false))
    }
    @Test fun disableAndActionRestrictionDoNotRetargetAWaitingToggle() {
        assertFalse(start.permits(QuickAccessSnapshot(enabled.copy(quickAccess=enabled.quickAccess.copy(enabled=false)),revision),false))
        assertFalse(start.permits(QuickAccessSnapshot(enabled.copy(quickAccess=enabled.quickAccess.copy(action="openApp")),revision),false))
        val open = QuickAccessAction(revision,"openApp",QuickAccessAction.Operation.OPEN)
        assertTrue(open.permits(QuickAccessSnapshot(enabled.copy(quickAccess=enabled.quickAccess.copy(action="openApp")),revision),false))
        assertFalse(open.permits(QuickAccessSnapshot(enabled,revision),false))
        assertFalse(open.copy(operation=QuickAccessAction.Operation.START,profile="b".repeat(64)).valid())
    }
    @Test fun unlockUpgradeAndIdenticalOptionABAInvalidateOldActions() {
        val unlockedPolicy=enabled.copy(quickAccess=enabled.quickAccess.copy(requireUnlock=false))
        assertTrue(start.permits(QuickAccessSnapshot(unlockedPolicy,revision),true))
        assertFalse(start.permits(QuickAccessSnapshot(enabled,"c".repeat(32)),true))
        val original=NativeOptionsStore.decode(NativeOptionsStore.encode(enabled,revision))
        val reapplied=NativeOptionsStore.decode(NativeOptionsStore.encode(enabled,"c".repeat(32)))
        assertEquals(original.options,reapplied.options)
        assertNotEquals(original.revision,reapplied.revision)
        assertFalse(start.permits(reapplied,false))
    }
    @Test fun actualActionClaimsAdvanceRevisionEvenWhenPreferencesAreUnchanged() {
        val directory=java.nio.file.Files.createTempDirectory("quick-action-revision").toFile()
        val context=org.mockito.Mockito.mock(android.content.Context::class.java)
        org.mockito.Mockito.`when`(context.noBackupFilesDir).thenReturn(directory)
        try {
            org.mockito.Mockito.mockConstruction(android.util.AtomicFile::class.java) {file,args ->
                val path=args.arguments()[0] as java.io.File
                org.mockito.Mockito.`when`(file.baseFile).thenReturn(path)
                org.mockito.Mockito.`when`(file.openRead()).thenAnswer {java.io.FileInputStream(path)}
                org.mockito.Mockito.`when`(file.startWrite()).thenAnswer {java.io.FileOutputStream(path)}
                org.mockito.Mockito.doAnswer {it.getArgument<java.io.FileOutputStream>(0).close();null}.`when`(file)
                    .finishWrite(org.mockito.Mockito.any(java.io.FileOutputStream::class.java))
            }.use {
                val store=NativeOptionsStore(context);store.write(enabled)
                val first=store.beginAction();val second=store.beginAction()
                assertEquals(first.options,second.options);assertNotEquals(first.revision,second.revision)
                assertFalse(start.copy(revision=first.revision).permits(second,false))
                store.invalidateActions();assertNotEquals(second.revision,store.readSnapshot().revision)
                assertEquals(setOf("flutter_vless_options_v1.json","flutter_vless_options_v1.lock"),directory.list()!!.toSet())
            }
        } finally {directory.deleteRecursively()}
    }
    @Test fun legacyBytesRemainReadableWithoutCreatingASecondCommitFile() {
        val raw="""{"quickAccess":{"enabled":true},"custom":"unchanged"}""".toByteArray()
        val legacy=NativeOptionsStore.decode(raw)
        assertEquals(64,legacy.revision.length)
        assertTrue(legacy.options.quickAccess.enabled)
        assertEquals(legacy,NativeOptionsStore.decode(raw))
        assertNotEquals(legacy.revision,NativeOptionsStore.decode(raw+byteArrayOf(32)).revision)
        assertThrows(IllegalArgumentException::class.java) {
            NativeOptionsStore.decode("""{"_quickAccessRevision":"bad"}""".toByteArray())
        }
    }
}
