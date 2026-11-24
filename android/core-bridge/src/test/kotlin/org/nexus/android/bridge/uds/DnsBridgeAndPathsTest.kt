package org.nexus.android.bridge.uds

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.nexus.android.bridge.dns.DnsBridgeCodec
import org.nexus.android.bridge.dns.DnsBridgeResponse
import org.nexus.android.bridge.ipc.NexusControlClient
import org.nexus.android.bridge.model.RuntimeSocketPaths
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

class DnsBridgeAndPathsTest {
    @Test
    fun validatesUnixSocketPathBelow108Bytes() {
        val okPaths = RuntimeSocketPaths(File("/data/user/0/org.nexus.android/no_backup"))
        okPaths.validatePaths()

        val tooLong = RuntimeSocketPaths(File("/" + "a".repeat(105)))
        assertThrows(IllegalArgumentException::class.java) {
            tooLong.validatePaths()
        }
    }

    @Test
    fun buildsNexus1ControlFrame() {
        val frame = NexusControlClient.buildNexus1Frame(listOf("select", "proxy", "hk-01"))!!
        assertEquals("NEXUS/1 select\u0000proxy\u0000hk-01", frame.toString(Charsets.UTF_8))
    }

    @Test
    fun roundTripsDnsBridgeRequestAndResponse() {
        val wireQuery = ByteArray(24) { it.toByte() }
        val buf = ByteBuffer.allocate(10 + wireQuery.size).order(ByteOrder.BIG_ENDIAN)
            .putInt(42)
            .putInt(2500)
            .putShort(wireQuery.size.toShort())
            .put(wireQuery)
            .array()

        val req = DnsBridgeCodec.readRequest(DataInputStream(ByteArrayInputStream(buf)))!!
        assertEquals(42, req.requestId)
        assertEquals(2500, req.timeoutMs)
        assertArrayEquals(wireQuery, req.wireQuery)

        val out = ByteArrayOutputStream()
        val answer = byteArrayOf(0x12, 0x34, 0x81.toByte(), 0x80.toByte())
        DnsBridgeCodec.writeResponse(
            DataOutputStream(out),
            DnsBridgeResponse(42, DnsBridgeCodec.STATUS_OK, 0, answer),
        )
        val encoded = ByteBuffer.wrap(out.toByteArray()).order(ByteOrder.BIG_ENDIAN)
        assertEquals(42, encoded.int)
        assertEquals(DnsBridgeCodec.STATUS_OK, encoded.get())
        assertEquals(0, encoded.int)
        assertEquals(4, encoded.short.toInt())
    }
}
