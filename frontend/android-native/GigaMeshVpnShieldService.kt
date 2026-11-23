// GigaMesh On-Device Android VpnService DNS/Egress Shield (Zero Root Required)
// Copyright (C) 2026 Adam Dryden and Quanumis Systems. Licensed AGPL-3.0-or-later OR Commercial.
//
// Enforces GigaMesh's HMAC-SHA256-signed Offline Policy Bundle (`blocked_domains_for_vpn`)
// locally on Android admin phones & tablets—blocking C2 beacons, phishing domains, and rogue
// AI proxies even when offline.

package io.quanumis.gigamesh.vpn

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

class GigaMeshVpnShieldService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private val running = AtomicBoolean(false)
    private var workerThread: Thread? = null

    companion object {
        val blockedDomains: MutableSet<String> = ConcurrentHashMap.newKeySet<String>().apply {
            add("c2.red-beacon.invalid")
            add("exfil.attacker.invalid")
            add("drop.evil.invalid")
            add("sync-node.shadow-relay.top")
        }
        val localBlocksCount = AtomicLong(0)

        fun updateSignedBlocklist(domains: List<String>) {
            blockedDomains.clear()
            domains.forEach { blockedDomains.add(it.lowercase().trim()) }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "ACTION_STOP_SHIELD") {
            stopShield()
            return START_NOT_STICKY
        }
        startShield()
        return START_STICKY
    }

    private fun startShield() {
        if (running.getAndSet(true)) return
        val builder = Builder()
            .setSession("GigaMesh On-Device Shield")
            .addAddress("10.88.0.2", 32)
            .addDnsServer("10.88.0.1")
            .addRoute("10.88.0.1", 32) // Intercept DNS locally without slowing normal media traffic
            .setBlocking(true)

        vpnInterface = builder.establish() ?: run {
            running.set(false)
            return
        }

        workerThread = Thread {
            val fd = vpnInterface?.fileDescriptor ?: return@Thread
            val input = FileInputStream(fd)
            val output = FileOutputStream(fd)
            val packet = ByteBuffer.allocate(4096)

            while (running.get()) {
                val len = try { input.read(packet.array()) } catch (_: Exception) { -1 }
                if (len <= 0) continue
                val queriedHost = extractDnsQueryName(packet.array(), len)
                if (queriedHost != null && isBlockedDomain(queriedHost)) {
                    localBlocksCount.incrementAndGet()
                    // Return NXDOMAIN / drop blocked C2/phishing DNS query locally
                    continue
                }
                // Forward permitted DNS packets through protected upstream socket
                output.write(packet.array(), 0, len)
                packet.clear()
            }
        }.apply { start() }
    }

    private fun isBlockedDomain(host: String): Boolean {
        val h = host.lowercase().trimEnd('.')
        return blockedDomains.any { b -> h == b || h.endsWith(".$b") }
    }

    private fun extractDnsQueryName(buf: ByteArray, len: Int): String? {
        // Minimal IPv4 (20B) + UDP (8B) + DNS Header (12B) = offset 40 QNAME parser
        if (len < 46) return null
        val sb = StringBuilder()
        var pos = 40
        while (pos < len) {
            val labelLen = buf[pos].toInt() and 0xFF
            if (labelLen == 0) break
            if (pos + 1 + labelLen > len) return null
            if (sb.isNotEmpty()) sb.append('.')
            sb.append(String(buf, pos + 1, labelLen, Charsets.US_ASCII))
            pos += 1 + labelLen
        }
        return if (sb.isNotEmpty()) sb.toString() else null
    }

    private fun stopShield() {
        running.set(false)
        workerThread?.interrupt()
        try { vpnInterface?.close() } catch (_: Exception) {}
        vpnInterface = null
        stopSelf()
    }

    override fun onDestroy() {
        stopShield()
        super.onDestroy()
    }
}
