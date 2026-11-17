package com.v2ray.ang.ui.main

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import kotlin.math.PI
import kotlin.math.sin

private val TigerOrange = Color(0xFFFF8F1F)
private val TigerDark = Color(0xFF222222)

/** Percent from "GsmBridge 47% - ..." (null if none). */
internal fun parseTorPercent(step: String): Int? =
    Regex("(\\d{1,3})%").find(step)?.groupValues?.get(1)?.toIntOrNull()?.coerceIn(0, 100)

/**
 * Live connection window: a tiger runs along a track; its position is the real
 * bootstrap percent and its pace grows with it. Not dismissable until finished.
 */
@Composable
fun TigerProgressDialog(
    c: UiColors,
    step: String,
    ready: Boolean,
    failed: Boolean,
    onClose: () -> Unit,
) {
    val pct = if (ready) 100 else (parseTorPercent(step) ?: 0)
    val progress by animateFloatAsState(pct / 100f, tween(700, easing = LinearEasing), label = "tigerProgress")

    LaunchedEffect(ready) {
        if (ready) {
            kotlinx.coroutines.delay(1000)
            onClose()
        }
    }

    Dialog(
        onDismissRequest = { if (failed) onClose() },
        properties = DialogProperties(dismissOnBackPress = failed, dismissOnClickOutside = false),
    ) {
        Surface(shape = RoundedCornerShape(24.dp), color = c.card) {
            Column(
                modifier = Modifier.fillMaxWidth().padding(20.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
            ) {
                Text(
                    text = if (failed) "\u2715" else "$pct%",
                    color = c.text, fontSize = 36.sp, fontWeight = FontWeight.ExtraBold,
                )
                Spacer(Modifier.height(8.dp))
                TigerTrack(progress = progress, running = !failed && !ready, accent = c.accent, trackColor = c.subText.copy(alpha = 0.25f))
                Spacer(Modifier.height(8.dp))
                Text(
                    text = if (ready) "\u2713" else step,
                    color = c.subText, fontSize = 12.sp, maxLines = 2,
                )
                if (failed) {
                    TextButton(onClick = onClose) { Text("OK", color = c.accent) }
                }
            }
        }
    }
}

@Composable
private fun TigerTrack(progress: Float, running: Boolean, accent: Color, trackColor: Color) {
    // Pace rises with progress: cycle 900 ms (slow) -> 280 ms (gallop).
    val cycleMs = (900 - 620 * progress).toInt().coerceAtLeast(250)
    val t = rememberInfiniteTransition(label = "tigerRun")
    val phase by t.animateFloat(
        initialValue = 0f, targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(cycleMs, easing = LinearEasing), RepeatMode.Restart),
        label = "phase",
    )
    Canvas(modifier = Modifier.fillMaxWidth().height(110.dp)) {
        val w = size.width
        val groundY = size.height - 14.dp.toPx()
        val tigerW = 72.dp.toPx()
        val margin = 8.dp.toPx()
        val x = margin + (w - 2 * margin - tigerW) * progress

        // track + filled part
        drawLine(trackColor, Offset(margin, groundY), Offset(w - margin, groundY), 5.dp.toPx(), StrokeCap.Round)
        drawLine(accent, Offset(margin, groundY), Offset(x + tigerW * 0.5f, groundY), 5.dp.toPx(), StrokeCap.Round)
        // ticks 0..100
        for (i in 0..4) {
            val tx = margin + (w - 2 * margin) * i / 4f
            drawLine(trackColor, Offset(tx, groundY + 4.dp.toPx()), Offset(tx, groundY + 10.dp.toPx()), 2.dp.toPx())
        }
        // finish flag
        val fx = w - margin
        drawLine(TigerDark, Offset(fx, groundY), Offset(fx, groundY - 40.dp.toPx()), 2.dp.toPx())
        drawRect(accent, Offset(fx - 18.dp.toPx(), groundY - 40.dp.toPx()), Size(18.dp.toPx(), 12.dp.toPx()))

        val p = if (running) phase else 0f
        // speed lines behind the tiger, longer with speed
        if (running) {
            val len = (10 + 40 * progress).dp.toPx()
            for (i in 0..2) {
                val ly = groundY - (18 + i * 14).dp.toPx()
                val off = ((p + i * 0.33f) % 1f) * 12.dp.toPx()
                drawLine(trackColor, Offset(x - off, ly), Offset(x - off - len, ly), 2.dp.toPx(), StrokeCap.Round)
            }
        }
        drawTiger(x, groundY, tigerW, p, running)
    }
}

private fun DrawScope.drawTiger(x: Float, groundY: Float, w: Float, p: Float, running: Boolean) {
    val u = w / 72f
    val bob = if (running) (sin(p * 2 * PI).toFloat() * 3f * u) else 0f
    val bodyTop = groundY - 40f * u + bob
    val bodyH = 22f * u
    val ang = (p * 2 * PI).toFloat()

    // legs: two pairs in opposite phase
    fun leg(lx: Float, phaseShift: Float) {
        val a = if (running) sin(ang + phaseShift) else 0f
        val hipY = bodyTop + bodyH
        val footX = lx + a * 10f * u
        val footY = groundY - (if (running && a > 0.3f) 4f * u else 0f)
        drawLine(TigerOrange, Offset(lx, hipY), Offset(footX, footY), 6f * u, StrokeCap.Round)
        drawLine(TigerDark, Offset(footX - 2f * u, footY), Offset(footX + 3f * u, footY), 6f * u, StrokeCap.Round)
    }
    leg(x + 14f * u, 0f)
    leg(x + 22f * u, PI.toFloat())
    leg(x + 46f * u, PI.toFloat())
    leg(x + 54f * u, 0f)

    // tail
    val tailWag = if (running) sin(ang * 2) * 5f * u else 0f
    drawLine(TigerOrange, Offset(x + 6f * u, bodyTop + 6f * u), Offset(x - 8f * u, bodyTop - 6f * u + tailWag), 4f * u, StrokeCap.Round)

    // body
    drawRoundRect(
        TigerOrange, Offset(x + 6f * u, bodyTop), Size(52f * u, bodyH),
        androidx.compose.ui.geometry.CornerRadius(11f * u),
    )
    // stripes
    for (i in 0..3) {
        val sx = x + (16f + i * 11f) * u
        drawLine(TigerDark, Offset(sx, bodyTop + 1f * u), Offset(sx - 2f * u, bodyTop + 12f * u), 3f * u, StrokeCap.Round)
    }
    // head
    val hx = x + 60f * u
    val hy = bodyTop + 2f * u
    drawCircle(TigerOrange, 10f * u, Offset(hx, hy))
    drawCircle(TigerOrange, 4f * u, Offset(hx - 6f * u, hy - 9f * u))
    drawCircle(TigerOrange, 4f * u, Offset(hx + 5f * u, hy - 9f * u))
    drawCircle(Color.White, 5f * u, Offset(hx + 7f * u, hy + 3f * u))
    drawCircle(TigerDark, 1.6f * u, Offset(hx + 4f * u, hy - 2f * u))
    drawCircle(TigerDark, 2f * u, Offset(hx + 11f * u, hy + 2f * u))
}
