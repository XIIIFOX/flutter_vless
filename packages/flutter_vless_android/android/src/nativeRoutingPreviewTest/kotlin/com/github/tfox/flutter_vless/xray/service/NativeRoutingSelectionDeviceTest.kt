package com.github.tfox.flutter_vless.xray.service

import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.ResultReceiver
import android.system.Os
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.github.tfox.flutter_vless.xray.core.BoundedCoreCommand
import com.github.tfox.flutter_vless.xray.core.NativeRoutingCommand
import com.github.tfox.flutter_vless.xray.core.XrayCoreManager
import com.github.tfox.flutter_vless.xray.dto.XrayConfig
import com.github.tfox.flutter_vless.xray.utils.AppConfigs
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.File
import java.io.InputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/** Actual optional routing CLI + ordinary production service/TUN. APK-only, never a writable executable copy. */
@RunWith(AndroidJUnit4::class)
class NativeRoutingSelectionDeviceTest {
    private val instrumentation=InstrumentationRegistry.getInstrumentation()
    private val context=instrumentation.targetContext
    private val manager=context.getSystemService(ConnectivityManager::class.java)
    private val run=UUID.randomUUID().toString().replace("-", "").take(12)
    private fun captured()=manager.getNetworkCapabilities(manager.activeNetwork)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)==true
    private fun digest(bytes:ByteArray)=MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    private fun await(description:String, seconds:Long=30, predicate:()->Boolean) {
        val deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(seconds)
        while(System.nanoTime()<deadline) { if(predicate()) return; Thread.sleep(50) }
        fail(description+"; "+XrayCoreManager.getProviderDebugSnapshot(context))
    }
    private fun verifyPreview() {
        check(Build.HARDWARE in setOf("ranchu","goldfish")) { "Disposable emulator only" }
        assertNull("VPN consent is required",VpnService.prepare(context))
        val expected=InstrumentationRegistry.getArguments().getString("routingPreviewSha256")
        require(expected?.matches(Regex("[0-9a-f]{64}"))==true) { "Verified routing APK input is required" }
        val preview=File(context.applicationInfo.nativeLibraryDir,"libxray_routing_preview.so")
        assertTrue("Routing preview was not extracted from APK",preview.isFile)
        assertEquals(expected,digest(preview.readBytes()))
        assertEquals(preview,XrayCoreManager.runtimeExecutable(context,true))
        assertNotEquals(preview,XrayCoreManager.runtimeExecutable(context,false))
        assertTrue("Actual optional CLI lacks capability1",XrayCoreManager.supportsNativeRouting(context))
        // Ordinary official runtime remains independently packaged and cannot silently accept the new option.
        val stock=ProcessBuilder(XrayCoreManager.runtimeExecutable(context,false).absolutePath,"native-routing","capabilities")
            .redirectErrorStream(true)
        stock.environment().remove("FLUTTER_VLESS_PROTECT_SOCKET")
        assertFalse("Legacy runtime unexpectedly advertised the optional factory",NativeRoutingCommand.capabilities(BoundedCoreCommand.capture(stock.start(),maxBytes=4096)))
    }
    private fun request(source:JSONObject, selection:Map<String,Any>, reconnect:Boolean=true):Int {
        val result=AtomicInteger(-1); val completed=CountDownLatch(1)
        val options="""{"reconnect":{"enabled":$reconnect,"initialDelayMs":200,"maxDelayMs":200,"maxAttempts":2}}"""
        context.startForegroundService(Intent(context,XrayVPNService::class.java)
            .putExtra("COMMAND",AppConfigs.V2RAY_SERVICE_COMMANDS.START_SERVICE)
            .putExtra("V2RAY_CONFIG",XrayConfig(V2RAY_FULL_JSON_CONFIG=source.toString(),
                VPN_ROUTING_SELECTION_JSON=NativeRoutingSelection.encode(selection,false),
                PLUGIN_OPTIONS_JSON=options,REMARK="Native routing regression"))
            .putExtra("start_receiver",object:ResultReceiver(Handler(Looper.getMainLooper())) {
                override fun onReceiveResult(code:Int,data:Bundle?) { result.set(code);completed.countDown() }
            }))
        assertTrue("Native admission result was lost",completed.await(15,TimeUnit.SECONDS))
        return result.get()
    }
    private fun connectedCount()=XrayCoreManager.getProviderDebugSnapshot(context).split("CONNECTED").size-1
    private fun ownedChildren():List<Int> {
        val executable=File(context.applicationInfo.nativeLibraryDir,"libxray_routing_preview.so").absolutePath
        return File("/proc").listFiles().orEmpty().mapNotNull { entry ->
            if(!entry.name.all(Char::isDigit)) return@mapNotNull null
            try {
                if(Os.stat(entry.path).st_uid!=android.os.Process.myUid()) return@mapNotNull null
                val arguments=File(entry,"cmdline").inputStream().use { input ->
                    val bytes=ByteArray(8192);val count=input.read(bytes)
                    if(count<=0) emptyList() else String(bytes,0,count,Charsets.UTF_8).split('\u0000')
                }
                if(arguments.firstOrNull()==executable && arguments.getOrNull(1)=="native-routing" &&
                    arguments.getOrNull(2)=="run") entry.name.toInt() else null
            } catch(_:Exception) { null } // The owned process may exit while /proc is being inspected.
        }
    }
    private fun ready(previous:Int?=null, before:Int=0):Int {
        await("Fresh optional routing child never became ready") {
            val children=ownedChildren()
            children.size==1 && children.single()!=previous && captured() && connectedCount()>before
        }
        return ownedChildren().single()
    }
    private fun stop() {
        val result=AtomicInteger(-1);val completed=CountDownLatch(1)
        context.startService(Intent(context,XrayVPNService::class.java)
            .putExtra("COMMAND",AppConfigs.V2RAY_SERVICE_COMMANDS.STOP_SERVICE)
            .putExtra("stop_receiver",object:ResultReceiver(Handler(Looper.getMainLooper())) {
                override fun onReceiveResult(code:Int,data:Bundle?) { result.set(code);completed.countDown() }
            }))
        assertTrue("Native Stop acknowledgement was lost",completed.await(15,TimeUnit.SECONDS))
        assertEquals("Native Stop did not drain its owner",0,result.get())
        await("Stop retained the optional child, authorization or capture",5) {
            !captured() && !AuthorizedProfileStore(context).exists() && ownedChildren().isEmpty()
        }
        assertFalse(context.noBackupFilesDir.listFiles().orEmpty().any { it.name.startsWith("xray-") && it.name.endsWith(".json") })
    }
    private fun runtimePair():Pair<ByteArray,JSONObject> {
        val config=context.noBackupFilesDir.listFiles().orEmpty().single {
            it.name.startsWith("xray-") && it.name.endsWith(".json") && !it.name.endsWith(".spec.json")
        }
        val bytes=config.readBytes(); val spec=JSONObject(File(config.parentFile,config.name.removeSuffix(".json")+".spec.json").readText())
        assertEquals(digest(bytes),spec.getString("source_sha256")); return bytes to spec
    }
    private fun withOccupiedPrivatePreferences(block:()->Unit) {
        val loopback=InetAddress.getByAddress(byteArrayOf(127,0,0,1))
        ServerSocket(10807,1,loopback).use {
            ServerSocket(10809,1,loopback).use { block() }
        }
    }
    private fun source(alias:String?, host:String, aliasOrigin:Origin, defaultOrigin:Origin):JSONObject {
        val port=ServerSocket(0,1,InetAddress.getByAddress(byteArrayOf(127,0,0,1))).use { it.localPort }
        val input=JSONObject().put("listen","127.0.0.1").put("port",port).put("protocol","http").put("settings",JSONObject())
        if(alias!=null) input.put("tag",alias)
        fun outbound(tag:String,origin:Origin)=JSONObject().put("tag",tag).put("protocol","freedom")
            .put("settings",JSONObject().put("redirect","127.0.0.1:${origin.port}"))
        // Limit marker traffic to the controlled destination port. Native DNS
        // and readiness guards must beat this caller block before alias/default selection.
        val rules=JSONArray().put(JSONObject().put("type","field")
            .put("port","1-18082,18084-65535").put("outboundTag","blocked-first"))
        if(alias!=null) {
            // The remaining controlled flow still exercises the source inbound alias.
            rules.put(JSONObject().put("type","field").put("inboundTag",JSONArray().put(alias)).put("outboundTag","alias-marker"))
        }
        return JSONObject().put("inbounds",JSONArray().put(input))
            .put("outbounds",JSONArray().put(JSONObject().put("tag","blocked-first").put("protocol","blackhole"))
                .put(outbound("alias-marker",aliasOrigin)).put(outbound("default-marker",defaultOrigin)))
            .put("dns",JSONObject().put("queryStrategy","UseIPv4").put("tag","caller-dns")
                .put("hosts",JSONObject().put("full:$host","10.0.2.2")).put("servers",JSONArray().put("localhost")))
            .put("routing",JSONObject().put("domainStrategy","AsIs").put("rules",rules))
    }
    private fun aliasRuleForUntagged(source:JSONObject) {
        source.getJSONObject("routing").getJSONArray("rules").put(JSONObject().put("type","field")
            .put("inboundTag",JSONArray().put("")).put("outboundTag","alias-marker"))
    }
    private fun assertSourceRetained(source:JSONObject, pair:Pair<ByteArray,JSONObject>, sourceIndex:Boolean) {
        val runtime=JSONObject(String(pair.first,Charsets.UTF_8)); val spec=pair.second
        assertEquals(1,spec.getInt("managed_inbound_index"))
        if(sourceIndex) assertEquals(0,spec.getInt("source_inbound_index")) else assertFalse(spec.has("source_inbound_index"))
        assertEquals("default-marker",spec.getString("default_outbound_tag"))
        assertEquals("[0,2]",spec.getJSONArray("guard_rule_indices").toString()) // API insertion shifts DNS, not an API guard.
        val socksPort=runtime.getJSONArray("inbounds").getJSONObject(spec.getInt("managed_inbound_index")).getInt("port")
        val apiRule=runtime.getJSONObject("routing").getJSONArray("rules").getJSONObject(1)
        assertEquals(runtime.getJSONObject("api").getString("tag"),apiRule.getString("outboundTag"))
        val apiTag=apiRule.getJSONArray("inboundTag").getString(0)
        val apiPort=(0 until runtime.getJSONArray("inbounds").length()).map { runtime.getJSONArray("inbounds").getJSONObject(it) }
            .single { it.optString("tag")==apiTag }.getInt("port")
        assertFalse("Generated SOCKS reused an occupied listener",socksPort in setOf(10807,10809))
        assertFalse("Generated API reused an occupied listener",apiPort in setOf(10807,10809))
        assertNotEquals(socksPort,apiPort)
        assertEquals(source.getJSONArray("inbounds").getJSONObject(0).toString(),runtime.getJSONArray("inbounds").getJSONObject(0).toString())
        assertEquals(source.getJSONObject("dns").toString(),runtime.getJSONObject("dns").toString())
        for(i in 0 until source.getJSONArray("outbounds").length())
            assertEquals(source.getJSONArray("outbounds").getJSONObject(i).toString(),runtime.getJSONArray("outbounds").getJSONObject(i).toString())
    }
    private fun dns(host:String) {
        val addresses=InetAddress.getAllByName(host)
        assertTrue("Caller Core hosts did not answer the OS resolver",addresses.any { it.hostAddress=="10.0.2.2" })
        assertEquals(listOf("198.18.0.2"),manager.getLinkProperties(manager.activeNetwork)?.dnsServers?.map { it.hostAddress })
    }
    private fun http(host:String,origin:Origin,other:Origin) {
        val progress=RoutingHttpProgress()
        try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(host,18083),3000);socket.soTimeout=3000
                progress.stage="SEND"
                socket.getOutputStream().write("GET /routing-$run HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n".toByteArray())
                val deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(5)
                val body=readRoutingHttp(socket.getInputStream(),progress) {
                    val left=TimeUnit.NANOSECONDS.toMillis(deadline-System.nanoTime())
                    check(left>0) { "Controlled HTTP deadline expired" }
                    socket.soTimeout=minOf(left,3000).toInt().coerceAtLeast(1)
                }
                assertArrayEquals("Wrong selected HTTP marker",origin.marker.toByteArray(Charsets.US_ASCII),body)
            }
        } catch(error:Throwable) {
            error.addSuppressed(IllegalStateException("Controlled HTTP stage=${progress.stage} headerBytes=${progress.headerBytes} bodyBytes=${progress.bodyBytes} declaredLength=${progress.declaredLength} selected=${origin.safeState()} other=${other.safeState()}"))
            throw error
        }
    }
    private fun udp(marker:String) {
        DatagramSocket().use { socket ->
            socket.soTimeout=3000
            val request="request-$run".toByteArray();val address=InetAddress.getByAddress(byteArrayOf(10,0,2,2))
            socket.send(DatagramPacket(request,request.size,address,18083))
            val reply=DatagramPacket(ByteArray(256),256);socket.receive(reply)
            assertEquals(address,reply.address);assertEquals(18083,reply.port)
            assertEquals(marker,String(reply.data,reply.offset,reply.length,Charsets.US_ASCII))
        }
    }
    @Test fun taggedAndUntaggedOriginalSourceContextKeepsPrivateDnsAndProbeGuards() {
        verifyPreview()
        withOccupiedPrivatePreferences {
        for(alias in listOf("caller-source", "")) {
            Origin("alias-$run",run).use { aliasOrigin -> Origin("default-$run",run).use { defaultOrigin ->
                // Core never matches an empty inbound tag, including a caller selector containing "".
                val selected=if(alias.isEmpty()) defaultOrigin else aliasOrigin
                val unused=if(alias.isEmpty()) aliasOrigin else defaultOrigin
                val host="alias-${if(alias.isEmpty())"empty" else "tagged"}-$run.dns-audit.invalid"
                val source=source(alias.takeIf { it.isNotEmpty() },host,aliasOrigin,defaultOrigin)
                if(alias.isEmpty()) aliasRuleForUntagged(source)
                val original=source.toString()
                try {
                    assertEquals(0,request(source,mapOf("sourceInboundIndex" to 0,"defaultOutboundTag" to "default-marker")))
                    ready();assertSourceRetained(source,runtimePair(),true)
                    assertEquals(0,selected.tcp.get());assertEquals(0,unused.tcp.get())
                    dns(host);http(host,selected,unused);udp(selected.marker)
                    assertEquals(original,source.toString())
                } finally { stop() }
                selected.close();unused.close();selected.checkCounts(1,1);unused.checkCounts(0,0)
                println(if(alias.isEmpty())"NATIVE_ROUTING_ALIAS_UNTAGGED_PASS" else "NATIVE_ROUTING_ALIAS_TAGGED_PASS")
            } }
        }
        }
    }
    @Test fun nonfirstDefaultSurvivesRejectedCandidateAndWorkerRecoveryWithFreshPair() {
        verifyPreview()
        withOccupiedPrivatePreferences {
        Origin("unused-$run",run).use { unused -> Origin("default-$run",run).use { selected ->
            val host="default-$run.dns-audit.invalid";val source=source(null,host,unused,selected);val original=source.toString()
            try {
                assertEquals(0,request(source,mapOf("defaultOutboundTag" to "default-marker")))
                val first=ready();val checked=runtimePair();assertSourceRetained(source,checked,false)
                dns(host);http(host,selected,unused)
                val invalid=JSONObject(source.toString())
                invalid.getJSONArray("outbounds").getJSONObject(0).put("protocol","not-a-registered-core-protocol")
                assertEquals(1,request(invalid,mapOf("defaultOutboundTag" to "default-marker")))
                assertEquals("Refused candidate replaced the accepted child",listOf(first),ownedChildren())
                assertArrayEquals(checked.first,runtimePair().first);assertTrue(captured());http(host,selected,unused)
                val beforeRecovery=connectedCount()
                assertEquals(listOf(first),ownedChildren())
                android.os.Process.killProcess(first) // Exact verified owned native child, never a global pkill.
                ready(first,beforeRecovery)
                assertFalse("Old native child was not reaped",File("/proc/$first").exists())
                val recovered=runtimePair();assertSourceRetained(source,recovered,false)
                assertNotEquals("Recovery reused the previous probe/config pair",checked.second.getString("source_sha256"),recovered.second.getString("source_sha256"))
                http(host,selected,unused);udp(selected.marker);assertEquals(original,source.toString())
            } finally { stop() }
            selected.close();unused.close();selected.checkCounts(3,1);unused.checkCounts(0,0)
            println("NATIVE_ROUTING_DEFAULT_RECOVERY_PASS")
        } }
        }
    }

    /** Device-owned TCP+UDP origins; exact counts also detect a guard sending private probes here. */
    private class Origin(val marker:String,private val run:String):Closeable {
        private val closed=AtomicBoolean(false)
        private val server=ServerSocket(0,8,InetAddress.getByAddress(byteArrayOf(127,0,0,1)))
        val port=server.localPort
        private val datagrams=try { DatagramSocket(port,InetAddress.getByAddress(byteArrayOf(127,0,0,1))) }
            catch(error:Throwable) { server.close();throw error }
        private val accepted=AtomicReference<Socket?>()
        private val failure=AtomicReference<Throwable?>()
        val tcp=AtomicInteger();val udp=AtomicInteger()
        private val acceptedTcp=AtomicInteger();private val requestHeaderBytes=AtomicInteger()
        private val tcpWorker=Thread({
            try { while(!closed.get()) {
                val client=try { server.accept() } catch(error:SocketException) { if(closed.get()) break else throw error }
                acceptedTcp.incrementAndGet()
                accepted.set(client)
                client.use {
                    if(closed.get()) return@use
                    it.soTimeout=3000
                    val header=ByteArrayOutputStream()
                    while(header.size()<4096 && !header.toString("US-ASCII").endsWith("\r\n\r\n")) {
                        val value=it.getInputStream().read();check(value>=0);header.write(value);requestHeaderBytes.incrementAndGet()
                    }
                    check(header.toString("US-ASCII").startsWith("GET /routing-$run HTTP/1.1\r\n"))
                    val body=marker.toByteArray(Charsets.US_ASCII)
                    it.getOutputStream().write("HTTP/1.1 200 OK\r\nContent-Length: ${body.size}\r\nConnection: close\r\n\r\n".toByteArray()+body)
                    tcp.incrementAndGet()
                }
                accepted.compareAndSet(client,null)
            } } catch(error:Throwable) { if(!closed.get()) failure.compareAndSet(null,error) }
        },"routing-marker-tcp").apply { isDaemon=true }
        private val udpWorker=Thread({
            try { while(!closed.get()) {
                val packet=DatagramPacket(ByteArray(256),256)
                try { datagrams.receive(packet) } catch(error:SocketException) { if(closed.get()) break else throw error }
                check(String(packet.data,packet.offset,packet.length,Charsets.US_ASCII)=="request-$run")
                val body=marker.toByteArray(Charsets.US_ASCII)
                datagrams.send(DatagramPacket(body,body.size,packet.address,packet.port));udp.incrementAndGet()
            } } catch(error:Throwable) { if(!closed.get()) failure.compareAndSet(null,error) }
        },"routing-marker-udp").apply { isDaemon=true }
        init {
            try { tcpWorker.start();udpWorker.start() }
            catch(error:Throwable) { try { close() } catch(cleanup:Throwable) { error.addSuppressed(cleanup) };throw error }
        }
        fun checkCounts(expectedTcp:Int,expectedUdp:Int) {
            failure.get()?.let { throw AssertionError("Owned routing marker failed",it) }
            assertEquals(expectedTcp,tcp.get());assertEquals(expectedTcp,acceptedTcp.get());assertEquals(expectedUdp,udp.get())
        }
        fun safeState()="tcp:${tcp.get()},accepted:${acceptedTcp.get()},requestHeaderBytes:${requestHeaderBytes.get()},udp:${udp.get()},failure:${failure.get()?.javaClass?.simpleName?.take(64)?:"none"}"
        override fun close() {
            if(!closed.compareAndSet(false,true)) return
            var primary:Throwable?=null;var interrupted=Thread.interrupted()
            fun attempt(action:()->Unit) { try { action() } catch(error:Throwable) { if(primary==null) primary=error else primary!!.addSuppressed(error) } }
            attempt { server.close() };attempt { datagrams.close() };attempt { accepted.getAndSet(null)?.close() }
            for(worker in listOf(tcpWorker,udpWorker)) {
                val deadline=System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(1500)
                while(worker.isAlive && System.nanoTime()<deadline) {
                    try { worker.join(TimeUnit.NANOSECONDS.toMillis(deadline-System.nanoTime()).coerceAtLeast(1)) }
                    catch(_:InterruptedException) { interrupted=true }
                }
                if(worker.isAlive) attempt { error("Owned routing marker did not drain") }
            }
            if(interrupted) Thread.currentThread().interrupt()
            primary?.let { throw it }
        }
    }
}

/** Controlled fixture framing only: a complete Content-Length body does not depend on a later FIN. */
private class RoutingHttpProgress {
    var stage="CONNECT"
    var headerBytes=0
    var bodyBytes=0
    var declaredLength=-1
}

private fun readRoutingHttp(input:InputStream,progress:RoutingHttpProgress,beforeRead:()->Unit):ByteArray {
    progress.stage="HEADERS"
    val header=ByteArrayOutputStream()
    while(!header.toString("US-ASCII").endsWith("\r\n\r\n")) {
        check(header.size()<4096) { "Controlled HTTP headers exceeded their bound" }
        beforeRead()
        val value=input.read()
        check(value>=0) { "Controlled HTTP headers were truncated" }
        header.write(value);progress.headerBytes=header.size()
    }
    val lines=header.toString("US-ASCII").split("\r\n")
    check(lines.first()=="HTTP/1.1 200 OK") { "Wrong selected HTTP status" }
    var length:Int?=null
    for(line in lines.drop(1).filter { it.isNotEmpty() }) {
        val separator=line.indexOf(':')
        check(separator>0) { "Controlled HTTP header was malformed" }
        val name=line.substring(0,separator)
        check(!name.equals("Transfer-Encoding",ignoreCase=true)) { "Controlled HTTP transfer encoding was unexpected" }
        if(name.equals("Content-Length",ignoreCase=true)) {
            check(length==null) { "Controlled HTTP length was duplicated" }
            val value=line.substring(separator+1).trim(' ','\t')
            check(value.isNotEmpty() && value.all { it in '0'..'9' }) { "Controlled HTTP length was malformed" }
            length=value.toIntOrNull()
            check(length!=null && length<=4096-header.size()) { "Controlled HTTP response exceeded its bound" }
        }
    }
    val size=checkNotNull(length) { "Controlled HTTP length was missing" }
    progress.declaredLength=size;progress.stage="BODY"
    val body=ByteArray(size)
    while(progress.bodyBytes<size) {
        beforeRead()
        val count=input.read(body,progress.bodyBytes,size-progress.bodyBytes)
        check(count>0) { "Controlled HTTP body was truncated" }
        progress.bodyBytes+=count
    }
    beforeRead() // Completion must still fit the same absolute deadline.
    progress.stage="COMPLETE"
    return body
}
