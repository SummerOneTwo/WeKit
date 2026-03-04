package moe.ouom.wekit.ui.creator.dialog.item.chat.risk

import android.content.Context
import android.text.InputType
import moe.ouom.wekit.ui.creator.dialog.BaseRikkaDialog

class WeRedPacketConfigDialog(context: Context) : BaseRikkaDialog(context, "自动抢红包") {

    override fun initPreferences() {
        addCategory("通用设置")

        addSwitchPreference(
            key = "red_packet_notification",
            title = "抢到后通知",
            summary = "在通知栏显示抢到的红包信息"
        )

        addCategory("高级选项")

        addSwitchPreference(
            key = "red_packet_self",
            title = "抢自己的红包",
            summary = "默认情况下不抢自己发出的"
        )

        addSwitchPreference(
            key = "red_packet_private_chat",
            title = "抢私聊红包",
            summary = "关闭后仅抢群聊红包，不抢私聊（1对1）的红包"
        )

        addEditTextPreference(
            key = "red_packet_delay_custom",
            title = "基础延迟",
            summary = "延迟时间",
            defaultValue = "1000",
            hint = "请输入延迟时间（毫秒）",
            inputType = InputType.TYPE_CLASS_NUMBER,
            maxLength = 5,
            summaryFormatter = { value ->
                if (value.isEmpty()) "0 ms" else "$value ms"
            }
        )

        addSwitchPreference(
            key = "red_packet_delay_random",
            title = "高斯随机延时",
            summary = "在基础延迟上按正态分布浮动，更自然地模拟人类反应"
        )

        addCategory("防检测")

        addSwitchPreference(
            key = "red_packet_rate_limit",
            title = "频率限制",
            summary = "每分钟最多抢 N 个红包，防止高频触发风控"
        )

        addEditTextPreference(
            key = "red_packet_max_per_min",
            title = "每分钟上限",
            summary = "最大抢包次数",
            defaultValue = "3",
            hint = "请输入每分钟最大次数",
            inputType = InputType.TYPE_CLASS_NUMBER,
            maxLength = 2,
            summaryFormatter = { value ->
                if (value.isEmpty()) "3 次/分钟" else "$value 次/分钟"
            }
        )

        addSwitchPreference(
            key = "red_packet_random_skip",
            title = "随机跳过",
            summary = "一定概率不抢，模拟\"没注意到\"的自然行为"
        )

        addEditTextPreference(
            key = "red_packet_skip_rate",
            title = "跳过概率",
            summary = "跳过红包的百分比",
            defaultValue = "15",
            hint = "请输入跳过概率（%）",
            inputType = InputType.TYPE_CLASS_NUMBER,
            maxLength = 2,
            summaryFormatter = { value ->
                if (value.isEmpty()) "15%" else "$value%"
            }
        )
    }
}