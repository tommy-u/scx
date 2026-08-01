(function (root, factory) {
  "use strict";

  const api = factory();
  root.MitosisCharts = api;
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const COLORS = {
    axis: "#758078",
    grid: "#dfe4e0",
    text: "#26312b",
    muted: "#758078",
    bar: "#2f7d62",
  };
  const FONT = '11px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';

  class History {
    constructor(maxPoints) {
      this.maxPoints = Math.max(1, Math.floor(Number(maxPoints) || 120));
      this.samples = [];
    }

    push(timestampMs, valuesObject) {
      if (!Number.isFinite(timestampMs)) {
        return;
      }
      this.samples.push({
        x: timestampMs,
        values: valuesObject && typeof valuesObject === "object" ? valuesObject : {},
      });
      if (this.samples.length > this.maxPoints) {
        this.samples.splice(0, this.samples.length - this.maxPoints);
      }
    }

    points(key) {
      const points = [];
      for (const sample of this.samples) {
        const value = sample.values[key];
        if (typeof value === "number" && Number.isFinite(value)) {
          points.push({ x: sample.x, y: value });
        }
      }
      return points;
    }

    clear() {
      this.samples.length = 0;
    }
  }

  function prepareCanvas(canvas) {
    if (!canvas || typeof canvas.getContext !== "function") {
      return null;
    }

    const bounds =
      typeof canvas.getBoundingClientRect === "function"
        ? canvas.getBoundingClientRect()
        : {};
    const cssWidth = positive(bounds.width) || positive(canvas.clientWidth) || 600;
    const cssHeight = positive(bounds.height) || positive(canvas.clientHeight) || 240;
    const browserDpr =
      typeof window !== "undefined" ? Number(window.devicePixelRatio) : 1;
    const dpr = Math.max(1, Math.min(4, positive(browserDpr) || 1));
    const pixelWidth = Math.max(1, Math.round(cssWidth * dpr));
    const pixelHeight = Math.max(1, Math.round(cssHeight * dpr));

    // Assigning either dimension resets the canvas, so only resize when needed.
    if (canvas.width !== pixelWidth) {
      canvas.width = pixelWidth;
    }
    if (canvas.height !== pixelHeight) {
      canvas.height = pixelHeight;
    }

    const context = canvas.getContext("2d");
    if (!context) {
      return null;
    }
    if (typeof context.setTransform === "function") {
      context.setTransform(dpr, 0, 0, dpr, 0, 0);
    }
    context.clearRect(0, 0, cssWidth, cssHeight);
    context.font = FONT;
    context.lineWidth = 1;
    context.textBaseline = "middle";
    return { context, width: cssWidth, height: cssHeight };
  }

  function positive(value) {
    return Number.isFinite(value) && value > 0 ? value : 0;
  }

  function formatValue(value, unit) {
    if (!Number.isFinite(value)) {
      return "-";
    }
    const magnitude = Math.abs(value);
    let rendered;
    if (magnitude >= 1000000) {
      rendered = `${(value / 1000000).toFixed(1)}M`;
    } else if (magnitude >= 1000) {
      rendered = `${(value / 1000).toFixed(1)}k`;
    } else if (magnitude >= 100) {
      rendered = value.toFixed(0);
    } else if (magnitude >= 10) {
      rendered = value.toFixed(1);
    } else {
      rendered = value.toFixed(2);
    }
    return unit ? `${rendered}${unit}` : rendered;
  }

  function drawEmpty(context, width, height) {
    context.fillStyle = COLORS.muted;
    context.textAlign = "center";
    context.fillText("No data", width / 2, height / 2);
  }

  function drawLineChart(canvas, series, options) {
    const surface = prepareCanvas(canvas);
    if (!surface) {
      return;
    }
    const { context, width, height } = surface;
    const config = options || {};
    const safeSeries = Array.isArray(series) ? series : [];
    const allPoints = [];
    for (const item of safeSeries) {
      if (!item || !Array.isArray(item.points)) {
        continue;
      }
      for (const point of item.points) {
        if (point && Number.isFinite(point.x) && Number.isFinite(point.y)) {
          allPoints.push(point);
        }
      }
    }
    if (!allPoints.length) {
      drawEmpty(context, width, height);
      return;
    }

    const xValues = allPoints.map((point) => point.x);
    const yValues = allPoints.map((point) => point.y);
    let xMin = Math.min(...xValues);
    let xMax = Math.max(...xValues);
    let yMin = Number.isFinite(config.minY)
      ? config.minY
      : Math.min(0, ...yValues);
    let yMax = Number.isFinite(config.maxY) ? config.maxY : Math.max(...yValues);
    if (xMin === xMax) {
      xMin -= 1;
      xMax += 1;
    }
    if (yMin === yMax) {
      yMax = yMin + Math.max(1, Math.abs(yMin) * 0.1);
    }
    if (yMin > yMax) {
      [yMin, yMax] = [yMax, yMin];
    }

    const margin = { top: 30, right: 12, bottom: 22, left: 54 };
    const plotWidth = Math.max(1, width - margin.left - margin.right);
    const plotHeight = Math.max(1, height - margin.top - margin.bottom);
    const mapX = (value) =>
      margin.left + ((value - xMin) / (xMax - xMin)) * plotWidth;
    const mapY = (value) =>
      margin.top + (1 - (value - yMin) / (yMax - yMin)) * plotHeight;

    drawYAxis(context, margin, width, plotHeight, yMin, yMax, config.unit);
    drawTimeAxis(context, margin, width, height, xMin, xMax);
    drawLegend(context, safeSeries, margin.left, 12, width - margin.left - 8);

    for (const item of safeSeries) {
      if (!item || !Array.isArray(item.points)) {
        continue;
      }
      context.strokeStyle = item.color || COLORS.bar;
      context.lineWidth = 1.5;
      context.beginPath();
      let drawing = false;
      for (const point of item.points) {
        if (!point || !Number.isFinite(point.x) || !Number.isFinite(point.y)) {
          drawing = false;
          continue;
        }
        if (drawing) {
          context.lineTo(mapX(point.x), mapY(point.y));
        } else {
          context.moveTo(mapX(point.x), mapY(point.y));
          drawing = true;
        }
      }
      context.stroke();
      context.fillStyle = item.color || COLORS.bar;
      for (const point of item.points) {
        if (!point || !Number.isFinite(point.x) || !Number.isFinite(point.y)) {
          continue;
        }
        context.beginPath();
        context.arc(mapX(point.x), mapY(point.y), 2, 0, Math.PI * 2);
        context.fill();
      }
    }
  }

  function drawTimeAxis(context, margin, width, height, min, max) {
    const label = (value) => new Date(value).toISOString().slice(11, 19);
    context.fillStyle = COLORS.axis;
    context.textAlign = "left";
    context.fillText(label(min), margin.left, height - 9);
    context.textAlign = "right";
    context.fillText(label(max), width - margin.right, height - 9);
  }

  function drawYAxis(context, margin, width, plotHeight, min, max, unit) {
    const ticks = 4;
    context.lineWidth = 1;
    for (let index = 0; index <= ticks; index += 1) {
      const ratio = index / ticks;
      const y = margin.top + ratio * plotHeight;
      const value = max - ratio * (max - min);
      context.strokeStyle = COLORS.grid;
      context.beginPath();
      context.moveTo(margin.left, y);
      context.lineTo(width - margin.right, y);
      context.stroke();
      context.fillStyle = COLORS.axis;
      context.textAlign = "right";
      context.fillText(formatValue(value, unit), margin.left - 7, y);
    }
  }

  function drawLegend(context, series, startX, y, maxWidth) {
    let x = startX;
    context.textAlign = "left";
    for (const item of series) {
      if (!item || !item.label || x >= startX + maxWidth) {
        continue;
      }
      const label = String(item.label);
      const itemWidth = Math.min(context.measureText(label).width + 28, maxWidth);
      if (x + itemWidth > startX + maxWidth) {
        break;
      }
      context.fillStyle = item.color || COLORS.bar;
      context.fillRect(x, y - 2, 12, 3);
      context.fillStyle = COLORS.text;
      context.fillText(label, x + 17, y);
      x += itemWidth;
    }
  }

  function drawBarChart(canvas, items, options) {
    const surface = prepareCanvas(canvas);
    if (!surface) {
      return;
    }
    const { context, width, height } = surface;
    const config = options || {};
    const safeItems = (Array.isArray(items) ? items : []).filter(
      (item) => item && Number.isFinite(item.value),
    );
    if (!safeItems.length) {
      drawEmpty(context, width, height);
      return;
    }

    const labelWidth = Math.min(130, Math.max(48, width * 0.28));
    const valueWidth = 66;
    const top = 8;
    const gap = 5;
    const rowHeight = Math.max(12, (height - top * 2) / safeItems.length - gap);
    const plotWidth = Math.max(1, width - labelWidth - valueWidth - 18);
    const maxValue = Math.max(0, ...safeItems.map((item) => item.value)) || 1;

    safeItems.forEach((item, index) => {
      const y = top + index * (rowHeight + gap);
      const value = Math.max(0, item.value);
      context.fillStyle = COLORS.text;
      context.textAlign = "right";
      context.fillText(truncate(context, String(item.label || ""), labelWidth - 12), labelWidth, y + rowHeight / 2);
      context.fillStyle = COLORS.grid;
      context.fillRect(labelWidth + 8, y, plotWidth, rowHeight);
      context.fillStyle = item.color || COLORS.bar;
      context.fillRect(labelWidth + 8, y, (value / maxValue) * plotWidth, rowHeight);
      context.fillStyle = COLORS.text;
      context.textAlign = "left";
      context.fillText(
        formatValue(item.value, config.unit),
        labelWidth + plotWidth + 14,
        y + rowHeight / 2,
      );
    });
  }

  function drawHistogram(canvas, buckets, options) {
    const surface = prepareCanvas(canvas);
    if (!surface) {
      return;
    }
    const { context, width, height } = surface;
    const config = options || {};
    const safeBuckets = (Array.isArray(buckets) ? buckets : []).filter(
      (bucket) => bucket && Number.isFinite(bucket.value),
    );
    if (!safeBuckets.length) {
      drawEmpty(context, width, height);
      return;
    }

    const margin = { top: 12, right: 12, bottom: 30, left: 48 };
    const plotWidth = Math.max(1, width - margin.left - margin.right);
    const plotHeight = Math.max(1, height - margin.top - margin.bottom);
    const maxValue = Math.max(0, ...safeBuckets.map((bucket) => bucket.value)) || 1;
    drawYAxis(context, margin, width, plotHeight, 0, maxValue, config.unit);

    const slotWidth = plotWidth / safeBuckets.length;
    const barWidth = Math.max(1, slotWidth - Math.min(5, slotWidth * 0.2));
    const labelStride = Math.max(1, Math.ceil(safeBuckets.length / Math.max(1, Math.floor(plotWidth / 64))));
    safeBuckets.forEach((bucket, index) => {
      const value = Math.max(0, bucket.value);
      const barHeight = (value / maxValue) * plotHeight;
      const x = margin.left + index * slotWidth + (slotWidth - barWidth) / 2;
      const y = margin.top + plotHeight - barHeight;
      context.fillStyle = COLORS.bar;
      context.fillRect(x, y, barWidth, barHeight);
      if (index % labelStride === 0 || index === safeBuckets.length - 1) {
        context.fillStyle = COLORS.axis;
        context.textAlign = "center";
        context.fillText(
          truncate(context, String(bucket.label || ""), slotWidth * labelStride - 4),
          x + barWidth / 2,
          height - 12,
        );
      }
    });
  }

  function truncate(context, text, maxWidth) {
    if (maxWidth <= 0 || context.measureText(text).width <= maxWidth) {
      return text;
    }
    let shortened = text;
    while (shortened.length > 1 && context.measureText(`${shortened}...`).width > maxWidth) {
      shortened = shortened.slice(0, -1);
    }
    return `${shortened}...`;
  }

  return { History, drawLineChart, drawBarChart, drawHistogram };
});
