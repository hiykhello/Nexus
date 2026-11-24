// Gaussian-blurred clamped Catmull-Rom Bezier wave SVG path generator.
#pragma once

namespace desktop_ui_helpers {
    struct WavePathPair {
        std::string area_cmd;
        std::string line_cmd;
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

    inline auto build_speed_wave_paths(
        std::span<const double> samples,
        std::size_t capacity = 24,
        double min_scale_kib = 8.0,
        double width = 240.0,
        double height = 80.0) -> WavePathPair {
        if (capacity < 2) capacity = 2;
        if (!(min_scale_kib > 0.0) || !std::isfinite(min_scale_kib)) min_scale_kib = 8.0;
        if (!(width > 0.0) || !std::isfinite(width)) width = 240.0;
        if (!(height > 4.0) || !std::isfinite(height)) height = 80.0;

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

        std::vector<double> heights(len, 0.0);
        for (std::size_t i = 0; i < len; ++i) {
            std::size_t const from = i > kRadius ? i - kRadius : 0;
            std::size_t const to = std::min(i + kRadius, len - 1);
            double sum = 0.0, weight = 0.0;
            for (std::size_t j = from; j <= to; ++j) {
                double w = kernel[j > i ? j - i : i - j];
                sum += w * padded[j];
                weight += w;
            }
            heights[i] = weight > 0.0 ? sum / weight : 0.0;
        }

        std::vector<double> slopes(len, 0.0);
        for (std::size_t i = 1; i + 1 < len; ++i) {
            double raw = (heights[i + 1] - heights[i - 1]) * 0.5;
            double lim = 3.0 * heights[i];
            slopes[i] = std::clamp(raw, -lim, lim);
        }

        std::size_t const start = len - capacity;
        double max_h = 0.0;
        for (std::size_t i = start; i < len; ++i) {
            max_h = std::max(max_h, heights[i]);
            if (i > start) {
                max_h = std::max(max_h, heights[i - 1] + slopes[i - 1] / 3.0);
                max_h = std::max(max_h, heights[i] - slopes[i] / 3.0);
            }
        }
        double const top = std::max(min_scale_kib, max_h * 1.08);
        double const y_scale = (height - 2.0) / top;
        double const step = width / static_cast<double>(capacity - 1);

        auto to_y = [&](double h) -> double {
            return std::clamp(height - h * y_scale, 0.0, height);
        };

        std::string line;
        line.reserve(capacity * 42);
        line += std::format("M 0.0 {:.1f}", to_y(heights[start]));
        for (std::size_t k = 1; k < capacity; ++k) {
            std::size_t const i = start + k;
            double const x0 = static_cast<double>(k - 1) * step;
            double const x1 = static_cast<double>(k) * step;
            double const cx1 = x0 + step / 3.0;
            double const cy1 = to_y(heights[i - 1] + slopes[i - 1] / 3.0);
            double const cx2 = x1 - step / 3.0;
            double const cy2 = to_y(heights[i] - slopes[i] / 3.0);
            double const y1 = to_y(heights[i]);
            line += std::format(" C {:.1f} {:.1f} {:.1f} {:.1f} {:.1f} {:.1f}", cx1, cy1, cx2, cy2, x1, y1);
        }
        std::string area = std::format("{} L {:.1f} {:.1f} L 0.0 {:.1f} Z", line, width, height + 4.0, height + 4.0);
        return {std::move(area), std::move(line)};
    }
}
