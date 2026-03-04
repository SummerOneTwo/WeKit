package moe.ouom.wekit.hooks.item.chat.risk

import android.annotation.SuppressLint
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.ContentValues
import android.content.Context
import android.os.Build
import androidx.core.net.toUri
import com.afollestad.materialdialogs.MaterialDialog
import de.robv.android.xposed.XposedHelpers
import moe.ouom.wekit.config.WeConfig
import moe.ouom.wekit.constants.Constants.Companion.TYPE_LUCKY_MONEY
import moe.ouom.wekit.constants.Constants.Companion.TYPE_LUCKY_MONEY_EXCLUSIVE
import moe.ouom.wekit.core.dsl.dexClass
import moe.ouom.wekit.core.dsl.dexMethod
import moe.ouom.wekit.core.model.BaseClickableFunctionHookItem
import moe.ouom.wekit.dexkit.intf.IDexFind
import moe.ouom.wekit.hooks.core.annotation.HookItem
import moe.ouom.wekit.hooks.sdk.api.WeDatabaseApi
import moe.ouom.wekit.hooks.sdk.api.WeDatabaseListener
import moe.ouom.wekit.hooks.sdk.api.WeNetworkApi
import moe.ouom.wekit.ui.creator.dialog.item.chat.risk.WeRedPacketConfigDialog
import moe.ouom.wekit.util.log.WeLogger
import org.json.JSONObject
import org.luckypray.dexkit.DexKitBridge
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import kotlin.random.Random

@SuppressLint("DiscouragedApi")
@HookItem(path = "聊天与消息/自动抢红包", desc = "监听消息并自动拆开红包")
class WeRedPacketAuto : BaseClickableFunctionHookItem(), WeDatabaseListener.DatabaseInsertListener, IDexFind {

    companion object {
        // [WeKit-Mod] 限流计数器
        private val grabCount = java.util.concurrent.atomic.AtomicInteger(0)
        private val lastResetTime = java.util.concurrent.atomic.AtomicLong(System.currentTimeMillis())
        private val rng = java.util.Random()

        private val rateLimitLock = Any()

        private fun canGrab(maxPerMinute: Int): Boolean {
            synchronized(rateLimitLock) {
                val now = System.currentTimeMillis()
                if (now - lastResetTime.get() > 60_000) {
                    grabCount.set(0)
                    lastResetTime.set(now)
                }
                return grabCount.incrementAndGet() <= maxPerMinute
            }
        }
    }

    private val dexClsReceiveLuckyMoney by dexClass()
    private val dexClsOpenLuckyMoney by dexClass()
    private val dexMethodOnGYNetEnd by dexMethod()
    private val dexMethodOnOpenGYNetEnd by dexMethod()

    private val currentRedPacketMap = ConcurrentHashMap<String, RedPacketInfo>()

    data class RedPacketInfo(
        val sendId: String,
        val nativeUrl: String,
        val talker: String,
        val msgType: Int,
        val channelId: Int,
        val headImg: String = "",
        val nickName: String = ""
    )

    override fun entry(classLoader: ClassLoader) {
        WeLogger.i("WeRedPacketAuto: entry() 被调用，开始注册数据库监听")
        // 注册数据库监听
        WeDatabaseListener.addListener(this)
        WeLogger.i("WeRedPacketAuto: 数据库监听器已注册")

        // Hook 具体的网络回调
        hookReceiveCallback()
        WeLogger.i("WeRedPacketAuto: 拆包网络回调 Hook 完成")

        // Hook 开包回调（用于检测是否抢到和获取金额）
        hookOpenCallback()
        WeLogger.i("WeRedPacketAuto: 开包网络回调 Hook 完成")
    }

    /**
     * 接口实现：处理数据库插入事件
     */
    override fun onInsert(table: String, values: ContentValues) {
        if (table != "message") return

        val type = values.getAsInteger("type") ?: 0
        if (type == TYPE_LUCKY_MONEY || type == TYPE_LUCKY_MONEY_EXCLUSIVE) {
            WeLogger.i("WeRedPacketAuto: 检测到红包消息 type=$type")
            handleRedPacket(values)
        }
    }

    private fun handleRedPacket(values: ContentValues) {
        try {
            val config = WeConfig.getDefaultConfig()
            if (values.getAsInteger("isSend") == 1 && !config.getBoolPrek("red_packet_self")) return

            // [WeKit-Mod] 私聊红包开关
            val talkerRaw = values.getAsString("talker") ?: ""
            val isGroupChat = talkerRaw.contains("@chatroom")
            if (!isGroupChat && !config.getBoolPrek("red_packet_private_chat")) {
                WeLogger.i("WeRedPacketAuto: 私聊红包已跳过（未开启私聊抢红包）")
                return
            }

            // [WeKit-Mod] 随机跳过（模拟“没看到”）
            val skipEnabled = config.getBoolPrek("red_packet_random_skip")
            val skipRate = config.getStringPrek("red_packet_skip_rate", "15")?.toFloatOrNull() ?: 15f
            if (skipEnabled && Random.nextFloat() * 100f < skipRate) {
                WeLogger.i("WeRedPacketAuto: 随机跳过本次红包（模拟自然行为）")
                return
            }

            // [WeKit-Mod] 频率限制
            val rateLimitEnabled = config.getBoolPrek("red_packet_rate_limit")
            val maxPerMin = (config.getStringPrek("red_packet_max_per_min", "3")?.toIntOrNull() ?: 3).coerceAtLeast(1)
            if (rateLimitEnabled && !canGrab(maxPerMin)) {
                WeLogger.i("WeRedPacketAuto: 频率限制触发，跳过本次红包（已达到每分钟上限 $maxPerMin 个，当前计数 ${grabCount.get()}）")
                return
            }

            val content = values.getAsString("content") ?: return
            val talker = values.getAsString("talker") ?: ""

            // 解析 XML 内容
            var xmlContent = content
            if (!content.startsWith("<") && content.contains(":")) {
                xmlContent = content.substring(content.indexOf(":") + 1).trim()
            }

            val nativeUrl = extractXmlParam(xmlContent, "nativeurl")
            if (nativeUrl.isEmpty()) return

            val uri = nativeUrl.toUri()
            val msgType = uri.getQueryParameter("msgtype")?.toIntOrNull() ?: 1
            val channelId = uri.getQueryParameter("channelid")?.toIntOrNull() ?: 1
            val sendId = uri.getQueryParameter("sendid") ?: ""
            val headImg = extractXmlParam(xmlContent, "headimgurl")
            val nickName = extractXmlParam(xmlContent, "sendertitle")

            if (sendId.isEmpty()) return

            WeLogger.i("WeRedPacketAuto: 发现红包 sendId=$sendId")

            currentRedPacketMap[sendId] = RedPacketInfo(
                sendId = sendId,
                nativeUrl = nativeUrl,
                talker = talker,
                msgType = msgType,
                channelId = channelId,
                headImg = headImg,
                nickName = nickName
            )

            // 处理延时
            val isRandomDelay = config.getBoolPrek("red_packet_delay_random")
            val customDelay = config.getStringPrek("red_packet_delay_custom", "0")?.toLongOrNull() ?: 0L

            WeLogger.i("WeRedPacketAuto: 配置读取 - isRandomDelay=$isRandomDelay, customDelay=$customDelay")

            // [WeKit-Mod] 高斯分布延迟，更自然的拟人效果
            val delayTime = if (isRandomDelay) {
                val baseDelay = (if (customDelay > 0) customDelay else 1000L).coerceAtLeast(300)
                val gaussian = rng.nextGaussian() // 正态分布 μ=0, σ=1
                val offset = (gaussian * (baseDelay * 0.4)).toLong() // 标准差为基础延迟的40%
                val finalDelay = (baseDelay + offset).coerceIn(300, baseDelay * 3)
                WeLogger.i("WeRedPacketAuto: 高斯延迟模式 - baseDelay=$baseDelay, offset=$offset, finalDelay=$finalDelay")
                finalDelay
            } else {
                WeLogger.i("WeRedPacketAuto: 固定延迟模式 - delayTime=$customDelay")
                customDelay
            }

            Thread {
                try {
                    WeLogger.i("WeRedPacketAuto: 开始延迟 ${delayTime}ms (sendId=$sendId)")
                    if (delayTime > 0) Thread.sleep(delayTime)

                    WeLogger.i("WeRedPacketAuto: 延迟结束，准备发送拆包请求 (sendId=$sendId)")
                    val req = XposedHelpers.newInstance(
                        dexClsReceiveLuckyMoney.clazz,
                        msgType, channelId, sendId, nativeUrl, 1, "v1.0", talker
                    )

                    WeNetworkApi.sendRequest(req)
                    WeLogger.i("WeRedPacketAuto: 拆包请求已发送 (sendId=$sendId)")
                } catch (e: Throwable) {
                    WeLogger.e("WeRedPacketAuto: 发送拆包请求失败 (sendId=$sendId)", e)
                }
            }.start()

        } catch (e: Throwable) {
            WeLogger.e("WeRedPacketAuto: 解析红包数据失败", e)
        }
    }

    private fun hookReceiveCallback() {
        try {
            dexMethodOnGYNetEnd.toDexMethod {
                hook {
                    afterIfEnabled { param ->
                        val json = param.args[2] as? JSONObject ?: return@afterIfEnabled
                        val sendId = json.optString("sendId")
                        val timingIdentifier = json.optString("timingIdentifier")

                        if (timingIdentifier.isNullOrEmpty() || sendId.isNullOrEmpty()) return@afterIfEnabled

                        val info = currentRedPacketMap[sendId] ?: return@afterIfEnabled
                        WeLogger.i("WeRedPacketAuto: 拆包成功，准备开包 ($sendId)")

                        Thread {
                            try {
                                val openReq = XposedHelpers.newInstance(
                                    dexClsOpenLuckyMoney.clazz,
                                    info.msgType, info.channelId, info.sendId, info.nativeUrl,
                                    info.headImg, info.nickName, info.talker,
                                    "v1.0", timingIdentifier, ""
                                )
                                // 使用 NetworkApi 发送（通知改由 hookOpenCallback 处理）
                                WeNetworkApi.sendRequest(openReq)
                                WeLogger.i("WeRedPacketAuto: 开包请求已发送 ($sendId)，等待 open 回调")

                                // 防止极端情况下 open 回调未触发导致 map 泄漏
                                Thread {
                                    try {
                                        Thread.sleep(5 * 60 * 1000L) // 5 分钟超时
                                        currentRedPacketMap.remove(sendId)?.let {
                                            WeLogger.w("WeRedPacketAuto: open 回调超时，主动清理红包记录 ($sendId)")
                                        }
                                    } catch (_: Throwable) {}
                                }.start()
                            } catch (e: Throwable) {
                                WeLogger.e("WeRedPacketAuto: 开包失败", e)
                                currentRedPacketMap.remove(sendId)
                            }
                        }.start()
                    }
                }
            }
        } catch (e: Throwable) {
            WeLogger.e("WeRedPacketAuto: Hook onGYNetEnd failed", e)
        }
    }

    private fun extractXmlParam(xml: String, tag: String): String {
        val pattern = "<$tag><!\\[CDATA\\[(.*?)]]></$tag>".toRegex()
        val match = pattern.find(xml)
        if (match != null) return match.groupValues[1]
        val patternSimple = "<$tag>(.*?)</$tag>".toRegex()
        val matchSimple = patternSimple.find(xml)
        return matchSimple?.groupValues?.get(1) ?: ""
    }

    /**
     * Hook OpenLuckyMoney 的 onGYNetEnd 回调
     * 只有在这个回调中才能确认是否真正抢到红包以及金额
     */
    private fun hookOpenCallback() {
        try {
            dexMethodOnOpenGYNetEnd.toDexMethod {
                hook {
                    afterIfEnabled { param ->
                        val json = param.args[2] as? JSONObject ?: return@afterIfEnabled
                        val sendId = json.optString("sendId")
                        if (sendId.isNullOrEmpty()) return@afterIfEnabled

                        // 打印完整回调日志，方便调试字段名（仅在调试级别输出）
                        WeLogger.d("WeRedPacketAuto: OpenLuckyMoney 回调 sendId=$sendId, json=$json")

                        val info = currentRedPacketMap.remove(sendId) ?: return@afterIfEnabled

                        // 检查是否成功抢到
                        val retcode = json.optInt("retcode", -1)
                        if (retcode != 0) {
                            WeLogger.i("WeRedPacketAuto: 未抢到红包 retcode=$retcode ($sendId)")
                            return@afterIfEnabled
                        }

                        // 获取金额（单位：分）
                        val recvAmount = json.optInt("recAmount", 0)
                        if (recvAmount <= 0) {
                            WeLogger.i("WeRedPacketAuto: 金额为0，跳过通知 ($sendId)")
                            return@afterIfEnabled
                        }

                        val amountYuan = recvAmount / 100.0
                        WeLogger.i("WeRedPacketAuto: 成功抢到红包 ¥$amountYuan ($sendId)")

                        // 通知逻辑
                        val notifyEnabled = WeConfig.getDefaultConfig().getBoolPrek("red_packet_notification")
                        if (notifyEnabled) {
                            // 解析来源名称
                            val sourceName = try {
                                WeDatabaseApi.INSTANCE?.getDisplayName(info.talker) ?: info.talker
                            } catch (_: Throwable) {
                                info.talker
                            }
                            val isGroup = info.talker.endsWith("@chatroom")
                            val sourceLabel = if (isGroup) "群聊" else "私聊"
                            showNotification(info, sourceName, sourceLabel, amountYuan)
                        }
                    }
                }
            }
        } catch (e: Throwable) {
            WeLogger.e("WeRedPacketAuto: Hook OpenLuckyMoney onGYNetEnd failed", e)
        }
    }

    // [WeKit-Mod] 抢到红包通知（含来源名称和金额）
    private fun showNotification(info: RedPacketInfo, sourceName: String, sourceLabel: String, amountYuan: Double) {
        try {
            val activity = moe.ouom.wekit.config.RuntimeConfig.getLauncherUIActivity()
            val context = activity?.applicationContext ?: activity ?: return
            val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return

            val channelId = "wekit_red_packet"
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                nm.createNotificationChannel(NotificationChannel(
                    channelId, "红包通知", NotificationManager.IMPORTANCE_HIGH
                ))
            }

            val amountStr = String.format(Locale.US, "%.2f", amountYuan)
            val contentText = "来自$sourceLabel【$sourceName】的 ¥$amountStr"

            val notification = android.app.Notification.Builder(context, channelId)
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setContentTitle("\uD83E\uDDE7 抢到红包")
                .setContentText(contentText)
                .setAutoCancel(true)
                .build()

            nm.notify(info.sendId.hashCode(), notification)
        } catch (t: Throwable) {
            WeLogger.e("WeRedPacketAuto: showNotification failed", t)
        }
    }

    override fun unload(classLoader: ClassLoader) {
        WeLogger.i("WeRedPacketAuto: unload() 被调用，移除数据库监听")
        WeDatabaseListener.removeListener(this)
        currentRedPacketMap.clear()
        WeLogger.i("WeRedPacketAuto: 数据库监听器已移除，红包缓存已清空")
        super.unload(classLoader)  // 必须调用父类方法来重置 isLoad 标志
    }

    override fun onClick(context: Context?) {
        context?.let { WeRedPacketConfigDialog(it).show() }
    }

    override fun dexFind(dexKit: DexKitBridge): Map<String, String> {
        val descriptors = mutableMapOf<String, String>()

        // 查找接收红包类
        dexClsReceiveLuckyMoney.find(dexKit, descriptors, allowMultiple = true) {
            matcher {
                methods {
                    add {
                        name = "<init>"
                        usingStrings("MicroMsg.NetSceneReceiveLuckyMoney")
                    }
                }
            }
        }

        // 查找开红包类
        val foundOpen = dexClsOpenLuckyMoney.find(dexKit, descriptors, allowMultiple = true) {
            matcher {
                methods {
                    add {
                        name = "<init>"
                        usingStrings("MicroMsg.NetSceneOpenLuckyMoney")
                    }
                }
            }
        }
        if (!foundOpen) {
            WeLogger.e("WeRedPacketAuto: Failed to find OpenLuckyMoney class")
            throw RuntimeException("DexKit: Failed to find OpenLuckyMoney class with string 'MicroMsg.NetSceneOpenLuckyMoney'")
        }

        // 查找 ReceiveLuckyMoney 的 onGYNetEnd 回调方法
        val receiveLuckyMoneyClassName = dexClsReceiveLuckyMoney.getDescriptorString()
        if (receiveLuckyMoneyClassName != null) {
            val foundMethod = dexMethodOnGYNetEnd.find(dexKit, descriptors,true) {
                matcher {
                    declaredClass = receiveLuckyMoneyClassName
                    name = "onGYNetEnd"
                    paramCount = 3
                }
            }
            if (!foundMethod) {
                WeLogger.e("WeRedPacketAuto: Failed to find ReceiveLuckyMoney onGYNetEnd method")
                throw RuntimeException("DexKit: Failed to find onGYNetEnd method in $receiveLuckyMoneyClassName")
            }
        }

        // 查找 OpenLuckyMoney 的 onGYNetEnd 回调方法
        val openLuckyMoneyClassName = dexClsOpenLuckyMoney.getDescriptorString()
        if (openLuckyMoneyClassName != null) {
            val foundOpenMethod = dexMethodOnOpenGYNetEnd.find(dexKit, descriptors, true) {
                matcher {
                    declaredClass = openLuckyMoneyClassName
                    name = "onGYNetEnd"
                    paramCount = 3
                }
            }
            if (!foundOpenMethod) {
                WeLogger.e("WeRedPacketAuto: Failed to find OpenLuckyMoney onGYNetEnd method")
                throw RuntimeException("DexKit: Failed to find onGYNetEnd method in $openLuckyMoneyClassName")
            }
        }

        return descriptors
    }

    override fun onBeforeToggle(newState: Boolean, context: Context): Boolean {
        if (newState) {
            MaterialDialog(context)
                .title(text = "警告")
                .message(text = "此功能可能导致账号异常，确定要启用吗?")
                .positiveButton(text = "确定") { dialog ->
                    applyToggle(true)
                }
                .negativeButton(text = "取消") { dialog ->
                    dialog.dismiss()
                }
                .show()

            // 返回 false 阻止自动切换
            return false
        }

        // 禁用功能时直接允许
        return true
    }
}