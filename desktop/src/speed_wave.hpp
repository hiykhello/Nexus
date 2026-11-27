// Gaussian-blurred clamped Catmull-Rom Bezier single & dual-track (dashed TX) SVG wave path generator.
#pragma once

namespace desktop_ui_helpers {
    struct WavePathPair {
        std::string area_cmd;
        std::string line_cmd;
    };

    struct DualWavePaths {
        std::string rx_area;
        std::string rx_line;
        std::string tx_dashed_line;
        double scale_top_kib = 8.0;
    };

    struct SplitRate {
        std::string value;
        std::string unit;
    };

    inline auto split_rate_parts(double kib_s) -> SplitRate {
        double v = (std::isfinite(kib_s) && kib_s > 0.0) ? kib_s : 0.0;
        if (v >= 1024.0) return {std::format("{:.1f}", v / 1024.0), "MB/s"};
        return {std::format("{:.1f}", v), "KB/s"};
    }

    namespace wave_detail {
        struct SmoothedSeries {
            std::vector<double> heights;
            std::vector<double> slopes;
            std::size_t start = 0;
            double max_h = 0.0;
        };

        inline auto smooth_series(std::span<const double> samples, std::size_t capacity) -> SmoothedSeries {
            constexpr double kSigma = 1.5;
            constexpr std::size_t kRadius = 4;
            std::array<double, kRadius + 1> kernel{};
            for (std::size_t d = 0; d <= kRadius; ++d) {
                double fd = static_cast<double>(d);
                kernel[d] = std::exp(-(fd * fd) / (2.0 * kSigma * kSigma));
            }
            std::size_t const len = capacity + kRadius + 1;
            std::vector<double> padded(len, 0.0);
            std::size_t const take = std::min(samples.size(), len);
            for (std::size_t k = 0; k < take; ++k) {
                double v = samples[samples.size() - take + k];
                padded[len - take + k] = (std::isfinite(v) && v > 0.0) ? v : 0.0;
            }
            SmoothedSeries out;
            out.heights.assign(len, 0.0);
            for (std::size_t i = 0; i < len; ++i) {
                std::size_t const from = i > kRadius ? i - kRadius : 0;
                std::size_t const to = std::min(i + kRadius, len - 1);
                double sum = 0.0, weight = 0.0;
                for (std::size_t j = from; j <= to; ++j) {
                    double w = kernel[j > i ? j - i : i - j];
                    sum += w * padded[j];
                    weight += w;
                }
                out.heights[i] = weight > 0.0 ? sum / weight : 0.0;
            }
            out.slopes.assign(len, 0.0);
            for (std::size_t i = 1; i + 1 < len; ++i) {
                double raw = (out.heights[i + 1] - out.heights[i - 1]) * 0.5;
                double lim = 3.0 * out.heights[i];
                out.slopes[i] = std::clamp(raw, -lim, lim);
            }
            out.start = len - capacity;
            for (std::size_t i = out.start; i < len; ++i) {
                out.max_h = std::max(out.max_h, out.heights[i]);
                if (i > out.start) {
                    out.max_h = std::max(out.max_h, out.heights[i - 1] + out.slopes[i - 1] / 3.0);
                    out.max_h = std::max(out.max_h, out.heights[i] - out.slopes[i] / 3.0);
                }
            }
            return out;
        }

        inline auto emit_solid_bezier(
            SmoothedSeries const& s,
            std::size_t capacity,
            double width,
            double height,
            double y_scale) -> std::string {
            auto to_y = [&](double h) -> double { return std::clamp(height - h * y_scale, 0.0, height); };
            double const step = width / static_cast<double>(capacity - 1);
            std::string line;
            line.reserve(capacity * 42);
            line += std::format("M 0.0 {:.1f}", to_y(s.heights[s.start]));
            for (std::size_t k = 1; k < capacity; ++k) {
                std::size_t const i = s.start + k;
                double const x0 = static_cast<double>(k - 1) * step;
                double const x1 = static_cast<double>(k) * step;
                double const cx1 = x0 + step / 3.0;
                double const cy1 = to_y(s.heights[i - 1] + s.slopes[i - 1] / 3.0);
                double const cx2 = x1 - step / 3.0;
                double const cy2 = to_y(s.heights[i] - s.slopes[i] / 3.0);
                double const y1 = to_y(s.heights[i]);
                line += std::format(" C {:.1f} {:.1f} {:.1f} {:.1f} {:.1f} {:.1f}", cx1, cy1, cx2, cy2, x1, y1);
            }
            return line;
        }

        // Pre-segmented true dashed SVG path along cubic Bezier curve (Slint Path lacks stroke-dasharray).
        inline auto emit_dashed_polyline(
            SmoothedSeries const& s,
            std::size_t capacity,
            double width,
            double height,
            double y_scale,
            double dash_len = 5.0,
            double gap_len = 3.5) -> std::string {
            auto to_y = [&](double h) -> double { return std::clamp(height - h * y_scale, 0.0, height); };
            double const step = width / static_cast<double>(capacity - 1);
            constexpr int kSub = 6;
            std::vector<std::pair<double, double>> pts;
            pts.reserve((capacity - 1) * kSub + 1);
            pts.emplace_back(0.0, to_y(s.heights[s.start]));
            for (std::size_t k = 1; k < capacity; ++k) {
                std::size_t const i = s.start + k;
                double const x0 = static_cast<double>(k - 1) * step;
                double const x1 = static_cast<double>(k) * step;
                double const y0 = to_y(s.heights[i - 1]);
                double const y1 = to_y(s.heights[i]);
                double const cx1 = x0 + step / 3.0;
                double const cy1 = to_y(s.heights[i - 1] + s.slopes[i - 1] / 3.0);
                double const cx2 = x1 - step / 3.0;
                double const cy2 = to_y(s.heights[i] - s.slopes[i] / 3.0);
                for (int m = 1; m <= kSub; ++m) {
                    double const t = static_cast<double>(m) / static_cast<double>(kSub);
                    double const u = 1.0 - t;
                    double const px = u * u * u * x0 + 3.0 * u * u * t * cx1 + 3.0 * u * t * t * cx2 + t * t * t * x1;
                    double const py = u * u * u * y0 + 3.0 * u * u * t * cy1 + 3.0 * u * t * t * cy2 + t * t * t * y1;
                    pts.emplace_back(px, py);
                }
            }
            std::string cmd;
            cmd.reserve(pts.size() * 14);
            bool drawing = true;
            double rem = dash_len;
            bool pen_open = false;
            auto emit_move = [&](double x, double y) {
                if (!cmd.empty()) cmd.push_back(' ');
                cmd += std::format("M {:.1f} {:.1f}", x, y);
                pen_open = true;
            };
            auto emit_line = [&](double x, double y) {
                cmd += std::format(" L {:.1f} {:.1f}", x, y);
            };
            for (std::size_t idx = 1; idx < pts.size(); ++idx) {
                double ax = pts[idx - 1].first, ay = pts[idx - 1].second;
                double const bx = pts[idx].first, by = pts[idx].second;
                double dx = bx - ax, dy = by - ay;
                double seg = std::hypot(dx, dy);
                while (seg > 1e-6) {
                    double take = std::min(seg, rem);
                    double frac = take / seg;
                    double nx = ax + dx * frac;
                    double ny = ay + dy * frac;
                    if (drawing) {
                        if (!pen_open) emit_move(ax, ay);
                        emit_line(nx, ny);
                    }
                    ax = nx; ay = ny;
                    dx = bx - ax; dy = by - ay;
                    seg -= take;
                    rem -= take;
                    if (rem <= 1e-6) {
                        drawing = !drawing;
                        rem = drawing ? dash_len : gap_len;
                        pen_open = false;
                    }
                }
            }
            return cmd;
        }
    }

    inline auto build_speed_wave_paths(
        std::span<const double> samples,
        std::size_t capacity = 24,
        double min_scale_kib = 8.0,
        double width = 320.0,
        double height = 44.0) -> WavePathPair {
        if (capacity < 2) capacity = 2;
        if (!(min_scale_kib > 0.0) || !std::isfinite(min_scale_kib)) min_scale_kib = 8.0;
        if (!(width > 0.0) || !std::isfinite(width)) width = 320.0;
        if (!(height > 4.0) || !std::isfinite(height)) height = 44.0;
        auto s = wave_detail::smooth_series(samples, capacity);
        double const top = std::max(min_scale_kib, s.max_h * 1.08);
        double const y_scale = (height - 2.0) / top;
        std::string line = wave_detail::emit_solid_bezier(s, capacity, width, height, y_scale);
        std::string area = std::format("{} L {:.1f} {:.1f} L 0.0 {:.1f} Z", line, width, height + 4.0, height + 4.0);
        return {std::move(area), std::move(line)};
    }

    inline auto build_dual_speed_wave_paths(
        std::span<const double> rx_samples,
        std::span<const double> tx_samples,
        std::size_t capacity = 24,
        double min_scale_kib = 8.0,
        double width = 560.0,
        double height = 56.0) -> DualWavePaths {
        if (capacity < 2) capacity = 2;
        if (!(min_scale_kib > 0.0) || !std::isfinite(min_scale_kib)) min_scale_kib = 8.0;
        if (!(width > 0.0) || !std::isfinite(width)) width = 560.0;
        if (!(height > 4.0) || !std::isfinite(height)) height = 56.0;
        auto rx = wave_detail::smooth_series(rx_samples, capacity);
        auto tx = wave_detail::smooth_series(tx_samples, capacity);
        double const top = std::max(min_scale_kib, std::max(rx.max_h, tx.max_h) * 1.08);
        double const y_scale = (height - 2.0) / top;
        std::string rx_line = wave_detail::emit_solid_bezier(rx, capacity, width, height, y_scale);
        std::string rx_area = std::format("{} L {:.1f} {:.1f} L 0.0 {:.1f} Z", rx_line, width, height + 4.0, height + 4.0);
        std::string tx_dashed = wave_detail::emit_dashed_polyline(tx, capacity, width, height, y_scale, 7.5, 4.5);
        return {std::move(rx_area), std::move(rx_line), std::move(tx_dashed), top};
    }
}
