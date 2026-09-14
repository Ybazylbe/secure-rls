import { BarChart3, Table2 } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import type { Answer, ChartSpec } from "@/api";
import { Table } from "@/components/Trace";
import { cn } from "@/lib/utils";

/*
 * Charts from the plot tool, drawn as plain SVG.
 *
 * The server prepares every figure -- group means, histogram bins, box-plot
 * quartiles -- so this file only maps numbers to pixels. One series per chart,
 * so one colour and no legend: the title says what is plotted. The colour is
 * the brand teal stepped until it passes the palette checks (lightness, chroma,
 * contrast against the white card); the brand's own #0b7e92 reads as grey on a
 * chart. Every mark answers hover and keyboard focus with its values, and every
 * chart has a table view, so no number is reachable only by pointing at it.
 */

const SERIES = "#0e8aa0";
const GRID = "#d9e5e9";
const RING = "#ffffff";

type Box = {
  n: number;
  min: number;
  q1: number;
  median: number;
  q3: number;
  max: number;
  whisker_low: number;
  whisker_high: number;
  outliers: number[];
};

type Tip = { x: number; y: number; title: string; lines: [string, string][] };

/** Every chart the tools produced for this answer, in the order they were made. */
export function Charts({ answer }: { answer: Answer }) {
  const charts = answer.steps
    .filter((step) => step.state === "ok" && !step.refused && step.chart)
    .map((step) => step.chart as ChartSpec);
  if (charts.length === 0) return null;
  return (
    <div className="space-y-3">
      {charts.map((chart, index) => (
        <ChartCard key={index} chart={chart} />
      ))}
    </div>
  );
}

/** One chart with its title, a hover readout, and a toggle to the table view. */
function ChartCard({ chart }: { chart: ChartSpec }) {
  const [asTable, setAsTable] = useState(false);
  const [tip, setTip] = useState<Tip | null>(null);
  const [frame, width] = useWidth();

  return (
    <div className="space-y-1.5 rounded-lg border border-line bg-white p-3">
      <div className="flex items-center gap-1.5 text-[0.8rem] font-medium text-ink/75">
        <BarChart3 className="size-3.5 text-ink/50" />
        <span className="first-letter:uppercase">{chart.title}</span>
        <button
          type="button"
          onClick={() => setAsTable((value) => !value)}
          className="ml-auto flex items-center gap-1 rounded-full border border-line px-2 py-0.5 text-[0.7rem] text-teal hover:bg-surface"
        >
          <Table2 className="size-3" />
          {asTable ? "Chart" : "Table"}
        </button>
      </div>

      {asTable ? (
        <Table rows={tableRows(chart)} total={chart.data.length} />
      ) : (
        <div ref={frame} className="relative" onPointerLeave={() => setTip(null)}>
          {width > 0 && chart.type === "bar" && <BarChart chart={chart} width={width} onTip={setTip} />}
          {width > 0 && chart.type === "histogram" && (
            <Histogram chart={chart} width={width} onTip={setTip} />
          )}
          {width > 0 && chart.type === "box" && <BoxPlot chart={chart} width={width} onTip={setTip} />}
          {tip && <Tooltip tip={tip} width={width} />}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// The three forms
// ---------------------------------------------------------------------------

type FormProps = { chart: ChartSpec; width: number; onTip: (tip: Tip | null) => void };

/** Group means as horizontal bars, largest first, each value written at the bar's tip. */
function BarChart({ chart, width, onTip }: FormProps) {
  const key = chart.x;
  const measure = chart.y ?? "";
  const rows = chart.data.map((row) => ({ label: String(row[key]), value: Number(row[measure]) }));
  const band = 32;
  const margin = { top: 4, right: 64, bottom: 24, left: 96 };
  const height = margin.top + rows.length * band + margin.bottom;
  const ticks = niceTicks(0, Math.max(...rows.map((r) => r.value)), 4);
  const x = scale(0, ticks.at(-1) ?? 1, margin.left, width - margin.right);
  const thickness = Math.min(24, band - 8);

  return (
    <svg width={width} height={height} role="img" aria-label={chart.title}>
      <XAxis ticks={ticks} x={x} top={margin.top} bottom={height - margin.bottom} />
      {rows.map((row, i) => {
        const y = margin.top + i * band + (band - thickness) / 2;
        const tip = () =>
          onTip({
            x: x(row.value),
            y,
            title: row.label,
            lines: [[label(measure), formatNumber(row.value)]],
          });
        return (
          <g key={row.label} tabIndex={0} onPointerMove={tip} onFocus={tip} onBlur={() => onTip(null)}
            className="outline-none focus-visible:[&>path]:opacity-80">
            <rect x={0} y={margin.top + i * band} width={width} height={band} fill="transparent" />
            <text x={margin.left - 8} y={y + thickness / 2} dy="0.35em" textAnchor="end"
              className="fill-ink/70 text-[11px]">
              {row.label}
            </text>
            <path d={barRight(x(0), y, x(row.value), thickness)} fill={SERIES} />
            <text x={x(row.value) + 6} y={y + thickness / 2} dy="0.35em"
              className="fill-ink/70 text-[11px] tabular-nums">
              {formatNumber(row.value)}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

/** Bin counts as touching columns separated by a 2px gap, on round bin edges. */
function Histogram({ chart, width, onTip }: FormProps) {
  const bins = chart.data.map((b) => ({ start: Number(b.start), end: Number(b.end), count: Number(b.count) }));
  const margin = { top: 8, right: 12, bottom: 28, left: 40 };
  const height = 220;
  const first = bins[0]?.start ?? 0;
  const last = bins.at(-1)?.end ?? 1;
  const x = scale(first, last, margin.left, width - margin.right);
  const yTicks = niceTicks(0, Math.max(...bins.map((b) => b.count)), 4);
  const y = scale(0, yTicks.at(-1) ?? 1, height - margin.bottom, margin.top);
  const every = bins.length > 8 ? 2 : 1;
  const edges = [...bins.map((b) => b.start), last].filter((_, i) => i % every === 0);

  return (
    <svg width={width} height={height} role="img" aria-label={chart.title}>
      {yTicks.map((tick) => (
        <g key={tick}>
          <line x1={margin.left} x2={width - margin.right} y1={y(tick)} y2={y(tick)} stroke={GRID} />
          <text x={margin.left - 6} y={y(tick)} dy="0.35em" textAnchor="end"
            className="fill-ink/50 text-[10px] tabular-nums">
            {formatNumber(tick)}
          </text>
        </g>
      ))}
      {edges.map((edge) => (
        <text key={edge} x={x(edge)} y={height - margin.bottom + 16} textAnchor="middle"
          className="fill-ink/50 text-[10px] tabular-nums">
          {compact(edge)}
        </text>
      ))}
      {bins.map((bin) => {
        const left = x(bin.start) + 1;
        const barWidth = Math.max(1, x(bin.end) - x(bin.start) - 2);
        const tip = () =>
          onTip({
            x: left + barWidth / 2,
            y: y(bin.count),
            title: `${formatNumber(bin.start)} – ${formatNumber(bin.end)}`,
            lines: [["employees", formatNumber(bin.count)]],
          });
        return (
          <g key={bin.start} tabIndex={0} onPointerMove={tip} onFocus={tip} onBlur={() => onTip(null)}
            className="outline-none">
            <rect x={x(bin.start)} y={margin.top} width={x(bin.end) - x(bin.start)}
              height={height - margin.top - margin.bottom} fill="transparent" />
            {bin.count > 0 && (
              <path d={columnUp(left, y(0), barWidth, y(bin.count))} fill={SERIES} />
            )}
          </g>
        );
      })}
    </svg>
  );
}

/** One horizontal box per group: whiskers, the middle half as a wash, the median, outliers. */
function BoxPlot({ chart, width, onTip }: FormProps) {
  const key = chart.x;
  const rows = chart.data.map((row) => ({ label: String(row[key]), box: row as unknown as Box }));
  const band = 36;
  const margin = { top: 4, right: 16, bottom: 24, left: 96 };
  const height = margin.top + rows.length * band + margin.bottom;
  const low = Math.min(...rows.map((r) => r.box.min));
  const high = Math.max(...rows.map((r) => r.box.max));
  const ticks = niceTicks(low, high, 5);
  const x = scale(ticks[0] ?? low, ticks.at(-1) ?? high, margin.left, width - margin.right);
  const boxHeight = 16;

  return (
    <svg width={width} height={height} role="img" aria-label={chart.title}>
      <XAxis ticks={ticks} x={x} top={margin.top} bottom={height - margin.bottom} />
      {rows.map(({ label: name, box }, i) => {
        const mid = margin.top + i * band + band / 2;
        const tip = () =>
          onTip({
            x: x(box.median),
            y: mid - boxHeight / 2,
            title: `${name} · ${box.n} employees`,
            lines: [
              ["median", formatNumber(box.median)],
              ["middle half", `${formatNumber(box.q1)} – ${formatNumber(box.q3)}`],
              ["range", `${formatNumber(box.min)} – ${formatNumber(box.max)}`],
              ["outliers", String(box.outliers.length)],
            ],
          });
        return (
          <g key={name} tabIndex={0} onPointerMove={tip} onFocus={tip} onBlur={() => onTip(null)}
            className="outline-none">
            <rect x={0} y={margin.top + i * band} width={width} height={band} fill="transparent" />
            <text x={margin.left - 8} y={mid} dy="0.35em" textAnchor="end" className="fill-ink/70 text-[11px]">
              {name}
            </text>
            <line x1={x(box.whisker_low)} x2={x(box.whisker_high)} y1={mid} y2={mid}
              stroke={SERIES} strokeWidth={2} strokeLinecap="round" opacity={0.55} />
            <rect x={x(box.q1)} y={mid - boxHeight / 2} width={Math.max(2, x(box.q3) - x(box.q1))}
              height={boxHeight} rx={4} fill={SERIES} opacity={0.22} />
            <line x1={x(box.median)} x2={x(box.median)} y1={mid - boxHeight / 2} y2={mid + boxHeight / 2}
              stroke={SERIES} strokeWidth={2} strokeLinecap="round" />
            {box.outliers.map((value, j) => (
              <circle key={j} cx={x(value)} cy={mid} r={4} fill={SERIES} stroke={RING} strokeWidth={2} />
            ))}
          </g>
        );
      })}
    </svg>
  );
}

// ---------------------------------------------------------------------------
// Shared pieces
// ---------------------------------------------------------------------------

/** Hairline vertical gridlines with values along the bottom. */
function XAxis({ ticks, x, top, bottom }: { ticks: number[]; x: (v: number) => number; top: number; bottom: number }) {
  return (
    <g>
      {ticks.map((tick) => (
        <g key={tick}>
          <line x1={x(tick)} x2={x(tick)} y1={top} y2={bottom} stroke={GRID} />
          <text x={x(tick)} y={bottom + 16} textAnchor="middle" className="fill-ink/50 text-[10px] tabular-nums">
            {compact(tick)}
          </text>
        </g>
      ))}
    </g>
  );
}

/** The readout for the mark under the pointer or keyboard focus: value first, label second. */
function Tooltip({ tip, width }: { tip: Tip; width: number }) {
  const flip = tip.x > width - 180;
  return (
    <div
      className={cn(
        "pointer-events-none absolute z-10 -translate-y-full rounded-lg border border-line bg-white px-2.5 py-1.5 shadow-sm",
        flip && "-translate-x-full",
      )}
      style={{ left: tip.x, top: tip.y - 6 }}
    >
      <p className="text-[0.72rem] text-ink/55">{tip.title}</p>
      {tip.lines.map(([name, value]) => (
        <p key={name} className="flex items-baseline gap-2 text-[0.78rem]">
          <span className="font-semibold tabular-nums text-ink">{value}</span>
          <span className="text-ink/50">{name}</span>
        </p>
      ))}
    </div>
  );
}

/** Rows for the table view; outlier lists are written out as text. */
function tableRows(chart: ChartSpec): Record<string, unknown>[] {
  return chart.data.map((row) =>
    Object.fromEntries(
      Object.entries(row).map(([k, v]) => [k, Array.isArray(v) ? v.map(formatNumber).join(", ") : v]),
    ),
  );
}

/** Track the width of a container, so charts are drawn at real pixel size. */
function useWidth(): [React.RefObject<HTMLDivElement | null>, number] {
  const ref = useRef<HTMLDivElement | null>(null);
  const [width, setWidth] = useState(0);
  useEffect(() => {
    const element = ref.current;
    if (!element) return;
    const observer = new ResizeObserver(([entry]) => setWidth(Math.floor(entry.contentRect.width)));
    observer.observe(element);
    return () => observer.disconnect();
  }, []);
  return [ref, width];
}

/** A linear mapping from data values to pixels. */
function scale(d0: number, d1: number, r0: number, r1: number) {
  const span = d1 - d0 || 1;
  return (value: number) => r0 + ((value - d0) / span) * (r1 - r0);
}

/** About ``count`` round tick values covering [low, high]. */
function niceTicks(low: number, high: number, count: number): number[] {
  if (high <= low) return [low, low + 1];
  const raw = (high - low) / count;
  const power = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 2.5, 5, 10].map((m) => m * power).find((s) => s >= raw) ?? raw;
  const start = Math.floor(low / step) * step;
  const ticks: number[] = [];
  for (let t = start; t < high + step; t += step) ticks.push(Number(t.toFixed(6)));
  return ticks;
}

/** A bar growing right from the baseline: square at the start, 4px rounded end. */
function barRight(x0: number, y: number, x1: number, h: number) {
  const r = Math.min(4, (x1 - x0) / 2, h / 2);
  return `M${x0},${y}H${x1 - r}Q${x1},${y} ${x1},${y + r}V${y + h - r}Q${x1},${y + h} ${x1 - r},${y + h}H${x0}Z`;
}

/** A column growing up from the baseline: square at the bottom, 4px rounded top. */
function columnUp(x: number, base: number, w: number, top: number) {
  const r = Math.min(4, w / 2, (base - top) / 2);
  return `M${x},${base}V${top + r}Q${x},${top} ${x + r},${top}H${x + w - r}Q${x + w},${top} ${x + w},${top + r}V${base}Z`;
}

function formatNumber(value: number) {
  return value.toLocaleString("en-US", { maximumFractionDigits: Math.abs(value) >= 100 ? 0 : 2 });
}

/** Axis labels: 120000 -> 120K, so ticks stay short. */
function compact(value: number) {
  return Math.abs(value) >= 1000
    ? `${(value / 1000).toLocaleString("en-US", { maximumFractionDigits: 1 })}K`
    : formatNumber(value);
}

function label(measure: string) {
  return measure.replace(/_/g, " ");
}
