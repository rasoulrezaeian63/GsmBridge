package com.v2ray.ang.ui.main

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
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
internal fun TigerProgressDialog(
    c: UiColors,
    step: String,
    ready: Boolean,
    failed: Boolean,
    onClose: () -> Unit,
) {
    val target = if (ready) 100 else (parseTorPercent(step) ?: 0)
    // shown percent only moves forward, at a bounded pace, so it never jumps to 100
    var shown by androidx.compose.runtime.remember { androidx.compose.runtime.mutableStateOf(0) }
    LaunchedEffect(target) {
        while (shown < target) {
            shown++
            kotlinx.coroutines.delay(if (target >= 100) 30L else 15L)
        }
    }
    val pct = shown
    val progress by animateFloatAsState(pct / 100f, tween(120, easing = LinearEasing), label = "tigerProgress")

    LaunchedEffect(ready, shown) {
        if (ready && shown >= 100) {
            kotlinx.coroutines.delay(700)
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
    val t = rememberInfiniteTransition(label = "dog")
    val bob by t.animateFloat(
        0f, -8f,
        infiniteRepeatable(tween(220, easing = LinearEasing), RepeatMode.Reverse), label = "bob",
    )
    androidx.compose.runtime.CompositionLocalProvider(
        androidx.compose.ui.platform.LocalLayoutDirection provides androidx.compose.ui.unit.LayoutDirection.Ltr,
    ) {
    androidx.compose.foundation.layout.BoxWithConstraints(Modifier.fillMaxWidth().height(110.dp)) {
        val dogW = 90.dp
        val x = (maxWidth - dogW) * progress
        androidx.compose.foundation.Image(
            painter = androidx.compose.ui.res.painterResource(com.v2ray.ang.R.drawable.dog_runner),
            contentDescription = null,
            contentScale = androidx.compose.ui.layout.ContentScale.Fit,
            modifier = Modifier
                .align(Alignment.BottomStart)
                .padding(bottom = 10.dp)
                .androidx_offset(x)
                .size(dogW)
                .graphicsLayer { translationY = if (running) bob else 0f },
        )
        Canvas(Modifier.fillMaxWidth().height(6.dp).align(Alignment.BottomCenter)) {
            drawRect(trackColor, Offset.Zero, size)
            drawRect(accent, Offset.Zero, Size(size.width * progress, size.height))
        }
    }
    }
}

private fun Modifier.androidx_offset(x: androidx.compose.ui.unit.Dp): Modifier =
    this.then(Modifier.offset(x = x))
