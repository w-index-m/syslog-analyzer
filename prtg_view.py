"""
PRTG 風ダッシュボードの表示部品（依存追加なし・SVGで自作）。

- svg_gauge():   車の速度計風ゲージ（緑/黄/赤ゾーン＋針＋数値）
- status_color(): alert_level → 信号機色
- gauge_spec_for(): SNMP oid_name からゲージ表示仕様（最大値・しきい値・単位）を決める
"""
import math

# 信号機カラー
STATUS_COLORS = {
    "none":     "#16a34a",  # 緑（正常）
    "ok":       "#16a34a",
    "normal":   "#16a34a",
    "warning":  "#f59e0b",  # 黄（注意）
    "warn":     "#f59e0b",
    "critical": "#dc2626",  # 赤（重大）
    "crit":     "#dc2626",
    "down":     "#6b7280",  # 灰（停止/不明）
    "unknown":  "#6b7280",
}


def status_color(level: str) -> str:
    return STATUS_COLORS.get((level or "none").lower(), "#6b7280")


def _polar(cx, cy, r, deg):
    a = math.radians(deg)
    return (cx + r * math.cos(a), cy - r * math.sin(a))


def _arc(cx, cy, r, start_deg, end_deg):
    """start_deg→end_deg（減少方向＝時計回り）の円弧パス。"""
    x1, y1 = _polar(cx, cy, r, start_deg)
    x2, y2 = _polar(cx, cy, r, end_deg)
    large = 1 if abs(start_deg - end_deg) > 180 else 0
    return f"M {x1:.1f} {y1:.1f} A {r} {r} 0 {large} 1 {x2:.1f} {y2:.1f}"


def svg_gauge(value, vmax, label="", unit="", warn=None, crit=None,
              width=220):
    """
    速度計風ゲージのSVG文字列を返す（180°半円）。
    value: 現在値 / vmax: 目盛り最大 / warn,crit: しきい値（Noneなら色分けなし）
    """
    try:
        v = float(value)
    except (TypeError, ValueError):
        v = 0.0
    vmax = float(vmax) if vmax else 100.0
    v = max(0.0, min(v, vmax))
    cx, cy, r = 100, 105, 80

    def ang(x):  # 値→角度（180°=左端, 0°=右端）
        return 180.0 * (1.0 - min(max(x, 0), vmax) / vmax)

    # ゾーン境界
    w = warn if warn is not None else vmax
    c = crit if crit is not None else vmax
    segs = []
    # 緑ゾーン 0→warn
    segs.append((_arc(cx, cy, r, 180, ang(w)), "#16a34a"))
    if warn is not None and w < c:
        segs.append((_arc(cx, cy, r, ang(w), ang(c)), "#f59e0b"))
    if crit is not None and c < vmax:
        segs.append((_arc(cx, cy, r, ang(c), 0), "#dc2626"))

    seg_svg = "".join(
        f'<path d="{d}" fill="none" stroke="{col}" stroke-width="16" '
        f'stroke-linecap="butt"/>' for d, col in segs)

    # 針
    na = ang(v)
    nx, ny = _polar(cx, cy, r - 10, na)
    # 現在値の色
    cur_col = "#16a34a"
    if crit is not None and v >= c:
        cur_col = "#dc2626"
    elif warn is not None and v >= w:
        cur_col = "#f59e0b"

    # 目盛りラベル（0 と max）
    x0, y0 = _polar(cx, cy, r + 14, 180)
    xm, ym = _polar(cx, cy, r + 14, 0)

    height = int(width * 0.72)
    return f'''
<svg viewBox="0 0 200 150" width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg">
  {seg_svg}
  <line x1="{cx}" y1="{cy}" x2="{nx:.1f}" y2="{ny:.1f}" stroke="#111827" stroke-width="3"/>
  <circle cx="{cx}" cy="{cy}" r="6" fill="#111827"/>
  <text x="{cx}" y="{cy-24}" text-anchor="middle" font-size="30" font-weight="bold" fill="{cur_col}">{v:.0f}</text>
  <text x="{cx}" y="{cy-6}" text-anchor="middle" font-size="13" fill="#6b7280">{unit}</text>
  <text x="{x0:.0f}" y="{y0+4:.0f}" text-anchor="middle" font-size="10" fill="#9ca3af">0</text>
  <text x="{xm:.0f}" y="{ym+4:.0f}" text-anchor="middle" font-size="10" fill="#9ca3af">{vmax:.0f}</text>
  <text x="{cx}" y="145" text-anchor="middle" font-size="13" font-weight="bold" fill="#374151">{label}</text>
</svg>'''


# oid_name → ゲージ仕様（最大値・しきい値・単位・表示名）
_GAUGE_SPECS = {
    "cpmCPUTotal5min": {"max": 100, "warn": 70, "crit": 90, "unit": "%", "label": "CPU(5分)"},
    "cpmCPUTotal1min": {"max": 100, "warn": 80, "crit": 95, "unit": "%", "label": "CPU(1分)"},
    "ciscoEnvMonTemperatureStatusValue": {"max": 100, "warn": 60, "crit": 75, "unit": "℃", "label": "温度"},
    "memory_used_pct": {"max": 100, "warn": 75, "crit": 90, "unit": "%", "label": "メモリ使用率"},
    "bandwidth_util_pct": {"max": 100, "warn": 70, "crit": 90, "unit": "%", "label": "帯域使用率"},
}


def gauge_spec_for(oid_name: str):
    """ゲージ表示すべき指標なら仕様を返す。対象外なら None。"""
    return _GAUGE_SPECS.get(oid_name)
