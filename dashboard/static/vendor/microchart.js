// dashboard/static/vendor/microchart.js - the one line chart this dashboard needs, drawn on a canvas.
//
// Replaces a 200 KB CDN dependency on Chart.js that existed to draw a single filled line. The lab runs on an isolated
// network, so a CDN asset is not a dependency, it is a guaranteed failure: before this file the CPU panel rendered as an
// empty bordered box and said so only in the browser console.
//
//   const c = new MicroLineChart(canvas, {min: 0, max: 100, suffix: "%"});
//   c.update(labels, values);
//
// Redraws on every update (the series is <= 60 points at 1 Hz, so there is nothing to optimise) and on resize.
(function (global) {
    "use strict";

    function css(el, name, fallback) {
        const v = getComputedStyle(el).getPropertyValue(name).trim();
        return v || fallback;
    }

    class MicroLineChart {
        constructor(canvas, opts) {
            this.canvas = canvas;
            this.o = Object.assign({min: 0, max: 100, suffix: "", yTicks: 5, xTicks: 8}, opts || {});
            this.labels = [];
            this.values = [];
            this._onResize = () => this.draw();
            global.addEventListener("resize", this._onResize);
        }

        update(labels, values) {
            this.labels = labels || [];
            this.values = (values || []).map(Number);
            this.draw();
        }

        draw() {
            const cv = this.canvas;
            const ratio = global.devicePixelRatio || 1;
            const w = cv.clientWidth || cv.parentElement.clientWidth || 600;
            const h = cv.clientHeight || 220;
            if (cv.width !== Math.round(w * ratio) || cv.height !== Math.round(h * ratio)) {
                cv.width = Math.round(w * ratio);
                cv.height = Math.round(h * ratio);
            }
            const x = cv.getContext("2d");
            x.setTransform(ratio, 0, 0, ratio, 0, 0);
            x.clearRect(0, 0, w, h);

            const ink = css(cv, "--text-dim", "#8899aa");
            const grid = css(cv, "--border", "rgba(255,255,255,0.12)");
            const line = css(cv, "--accent", "#4da3ff");
            const padL = 44, padR = 10, padT = 10, padB = 22;
            const plotW = Math.max(w - padL - padR, 10);
            const plotH = Math.max(h - padT - padB, 10);
            const {min, max} = this.o;
            const yOf = (v) => padT + plotH * (1 - (Math.min(Math.max(v, min), max) - min) / (max - min || 1));

            x.strokeStyle = grid;
            x.fillStyle = ink;
            x.lineWidth = 1;
            x.font = "11px ui-monospace, monospace";
            x.textBaseline = "middle";
            x.textAlign = "right";
            for (let i = 0; i <= this.o.yTicks; i++) {
                const v = min + (max - min) * (i / this.o.yTicks);
                const y = Math.round(yOf(v)) + 0.5;
                x.beginPath();
                x.moveTo(padL, y);
                x.lineTo(padL + plotW, y);
                x.stroke();
                x.fillText(`${Math.round(v)}${this.o.suffix}`, padL - 6, y);
            }

            const n = this.values.length;
            if (!n) {
                x.textAlign = "center";
                x.fillText("no data yet", padL + plotW / 2, padT + plotH / 2);
                return;
            }
            const xOf = (i) => padL + (n === 1 ? plotW / 2 : plotW * (i / (n - 1)));

            x.beginPath();
            x.moveTo(xOf(0), yOf(this.values[0]));
            for (let i = 1; i < n; i++) {
                x.lineTo(xOf(i), yOf(this.values[i]));
            }
            x.lineTo(xOf(n - 1), padT + plotH);
            x.lineTo(xOf(0), padT + plotH);
            x.closePath();
            const grad = x.createLinearGradient(0, padT, 0, padT + plotH);
            grad.addColorStop(0, "rgba(77,163,255,0.28)");
            grad.addColorStop(1, "rgba(77,163,255,0.02)");
            x.fillStyle = grad;
            x.fill();

            x.beginPath();
            x.moveTo(xOf(0), yOf(this.values[0]));
            for (let i = 1; i < n; i++) {
                x.lineTo(xOf(i), yOf(this.values[i]));
            }
            x.strokeStyle = line;
            x.lineWidth = 2;
            x.lineJoin = "round";
            x.stroke();

            x.fillStyle = ink;
            x.textAlign = "center";
            x.textBaseline = "top";
            const step = Math.max(1, Math.ceil(n / this.o.xTicks));
            for (let i = 0; i < n; i += step) {
                x.fillText(String(this.labels[i] ?? ""), xOf(i), padT + plotH + 5);
            }
        }

        destroy() {
            global.removeEventListener("resize", this._onResize);
        }
    }

    global.MicroLineChart = MicroLineChart;
})(window);
